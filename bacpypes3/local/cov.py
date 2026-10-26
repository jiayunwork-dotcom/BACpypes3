"""
Change Of Value
"""
from __future__ import annotations

import asyncio

from functools import partial

from typing import Callable, Dict, List, Optional, Tuple

from ..debugging import bacpypes_debugging, ModuleLogger
from ..primitivedata import ObjectType
from ..basetypes import PropertyValue
from ..constructeddata import Any
from ..apdu import (
    ConfirmedCOVNotificationRequest,
    UnconfirmedCOVNotificationRequest,
)
from ..object import DeviceObject
from ..service.cov import PropertySubscription

# some debugging
_debug = 0
_log = ModuleLogger(globals())

#
#   DetectionMonitor
#


@bacpypes_debugging
class DetectionMonitor:
    """
    An instance of this class is used to associate a property of an
    object to a parameter of a COV algorithm.  The property_change()
    function is called when the property changes value and that
    value is passed along as an attribute of the algorithm.
    """

    _debug: Callable[..., None]

    def __init__(self, algorithm, parameter, obj, prop, filter=None):
        if _debug:
            DetectionMonitor._debug("__init__ ... %r ...", parameter)

        # keep track of the parameter values
        self.algorithm = algorithm
        self.parameter = parameter
        self.obj = obj
        self.prop = prop
        self.filter = None

    def property_change(self, old_value, new_value):
        if _debug:
            DetectionMonitor._debug("property_change %r %r", old_value, new_value)

        # set the parameter value
        setattr(self.algorithm, self.parameter, new_value)

        # if the algorithm is scheduled to run, don't bother checking for more
        if self.algorithm._execute_handle:
            if _debug:
                DetectionMonitor._debug("    - already scheduled")
            return

        # if there is a special filter, use it, otherwise use !=
        if self.filter:
            change_found = self.filter(old_value, new_value)
        else:
            change_found = old_value != new_value
        if _debug:
            DetectionMonitor._debug("    - change_found: %r", change_found)

        # schedule it
        if change_found and not self.algorithm._execute_handle:
            self.algorithm._execute_handle = asyncio.get_event_loop().call_soon(
                self.algorithm._execute
            )
            if _debug:
                DetectionMonitor._debug(
                    "    - deferred: %r", self.algorithm._execute_handle
                )


#
#   monitor_filter
#


def monitor_filter(parameter):
    def transfer_filter_decorator(fn):
        fn._monitor_filter = parameter
        return fn

    return transfer_filter_decorator


#
#   DetectionAlgorithm
#


@bacpypes_debugging
class DetectionAlgorithm:
    _debug: Callable[..., None]

    _monitors: List[DetectionMonitor]
    _execute_handle: asyncio.Handle

    def __init__(self):
        if _debug:
            DetectionAlgorithm._debug("__init__")

        # monitor objects
        self._monitors = []

        # handle for being scheduled to run
        self._execute_handle = None

    def bind(self, **kwargs):
        if _debug:
            DetectionAlgorithm._debug("bind %r", kwargs)

        # build a map of methods that are filters.  These have been decorated
        # with monitor_filter, but they are unbound methods (or simply
        # functions in Python3) at the time they are decorated but by looking
        # for them now they are bound to this instance.
        monitor_filters = {}
        for attr_name in dir(self):
            attr = getattr(self, attr_name)
            if hasattr(attr, "_monitor_filter"):
                monitor_filters[attr._monitor_filter] = attr
        if _debug:
            DetectionAlgorithm._debug("    - monitor_filters: %r", monitor_filters)

        for parameter, (obj, prop) in kwargs.items():
            if not hasattr(self, parameter):
                if _debug:
                    DetectionAlgorithm._debug(
                        "    - no matching parameter: %r", parameter
                    )

            # make a detection monitor
            monitor = DetectionMonitor(self, parameter, obj, prop)
            if _debug:
                DetectionAlgorithm._debug("    - monitor: %r", monitor)

            # check to see if there is a custom filter for it
            if parameter in monitor_filters:
                monitor.filter = monitor_filters[parameter]

            # keep track of all of these objects for if/when we unbind
            self._monitors.append(monitor)

            # add the property value monitor function
            obj._property_monitors[prop].append(monitor.property_change)

            # set the parameter value to the property value if it's not None
            property_value = getattr(obj, prop)
            if property_value is not None:
                if _debug:
                    DetectionAlgorithm._debug("    - %s: %r", parameter, property_value)
                setattr(self, parameter, property_value)

    def unbind(self):
        if _debug:
            DetectionAlgorithm._debug("unbind")

        # remove the property value monitor functions
        for monitor in self._monitors:
            if _debug:
                DetectionAlgorithm._debug("    - monitor: %r", monitor)
            monitor.obj._property_monitors[monitor.prop].remove(monitor.property_change)

        # abandon the array
        self._monitors = []

    def _execute(self):
        if _debug:
            DetectionAlgorithm._debug("_execute")

        # no longer scheduled
        self._execute_handle = None

        # provided by the derived class
        self.execute()

    def execute(self):
        raise NotImplementedError("execute not implemented")


#
#   COVDetection
#


@bacpypes_debugging
class COVDetection(DetectionAlgorithm):
    properties_tracked = ()
    properties_reported = ()
    monitored_property_reference = None

    def __init__(self, obj) -> None:
        if _debug:
            COVDetection._debug("__init__ %r", obj)
        DetectionAlgorithm.__init__(self)

        # keep track of the object
        self.obj = obj

        # build a list of parameters and matching object property references
        kwargs = {}
        for property_name in self.properties_tracked:
            setattr(self, property_name, None)
            kwargs[property_name] = (obj, property_name)

        # let the base class set up the bindings and initial values
        self.bind(**kwargs)

        # list of all active object-level subscriptions
        self.cov_subscriptions = []

        # property-level subscriptions, a list keyed by
        # (property name, property array index)
        self.cov_property_subscriptions: Dict[
            Tuple[str, Optional[int]], List[PropertySubscription]
        ] = {}

        # property change monitor functions installed for the
        # property-level subscriptions, keyed the same way
        self._cov_property_monitors: Dict[
            Tuple[str, Optional[int]], Callable[..., None]
        ] = {}

    def add_subscription(self, cov) -> None:
        if _debug:
            COVDetection._debug("add_subscription %r", cov)

        # property-level subscriptions are kept separate from the
        # object-level ones and get their own monitor on the property
        if isinstance(cov, PropertySubscription):
            key = (cov.prop_id, cov.prop_index)
            if _debug:
                COVDetection._debug("    - key: %r", key)

            self.cov_property_subscriptions.setdefault(key, []).append(cov)

            # install a monitor on the property for the first subscription
            if key not in self._cov_property_monitors:
                monitor = partial(self._cov_property_change, key)
                self._cov_property_monitors[key] = monitor
                self.obj._property_monitors[cov.prop_id].append(monitor)
            return

        # add it to the subscription list for its object
        self.cov_subscriptions.append(cov)

    def cancel_subscription(self, cov) -> None:
        if _debug:
            COVDetection._debug("cancel_subscription %r", cov)

        # cancel the subscription timeout
        cov.cancel_subscription()

        if isinstance(cov, PropertySubscription):
            key = (cov.prop_id, cov.prop_index)

            # remove it from the property subscription list
            property_subscriptions = self.cov_property_subscriptions.get(key, None)
            if property_subscriptions is not None:
                property_subscriptions.remove(cov)

                # when the last subscription for the property goes away
                # remove the monitor and the list
                if not property_subscriptions:
                    del self.cov_property_subscriptions[key]

                    monitor = self._cov_property_monitors.pop(key, None)
                    if monitor is not None:
                        self.obj._property_monitors[cov.prop_id].remove(monitor)
            return

        # remove it from the subscription list for its object
        self.cov_subscriptions.remove(cov)

    def unbind(self) -> None:
        if _debug:
            COVDetection._debug("unbind")

        # remove the property-level monitor functions
        for (prop_id, _prop_index), monitor in self._cov_property_monitors.items():
            if _debug:
                COVDetection._debug("    - prop_id, monitor: %r %r", prop_id, monitor)
            self.obj._property_monitors[prop_id].remove(monitor)
        self._cov_property_monitors = {}

        # abandon the property-level subscription lists
        self.cov_property_subscriptions = {}

        # remove the object-level monitor functions
        DetectionAlgorithm.unbind(self)

    def execute(self) -> None:
        """
        By default if one of the properties that are being tracked have changed
        then send out COV notifications to all of the active subscriptions.
        """
        if _debug:
            COVDetection._debug("execute")

        # something changed, send out the notifications
        self.send_cov_notifications()

    def send_cov_notifications(self, subscription=None) -> None:
        """
        Send out COV notifications to a specific subscription when it has
        newly joined, or all of the active subscriptions.
        """
        if _debug:
            COVDetection._debug("send_cov_notifications %r", subscription)

        # check for subscriptions
        if not len(self.cov_subscriptions):
            return

        # create a list of PropertyValue objects
        list_of_values = []
        for property_name in self.properties_reported:
            if _debug:
                COVDetection._debug("    - property_name: %r", property_name)

            property_value = getattr(self, property_name)
            if _debug:
                COVDetection._debug("    - property_value: %r", property_value)

            # bundle it into a sequence
            property_value = PropertyValue(
                propertyIdentifier=property_name,
                value=Any(property_value),
            )

            # add it to the list
            list_of_values.append(property_value)
        if _debug:
            COVDetection._debug("    - list_of_values: %r", list_of_values)

        # if the specific subscription was provided, that is the notification
        # list, otherwise send it to all of them
        if subscription is not None:
            notification_list = [subscription]
        else:
            notification_list = self.cov_subscriptions

        # get the current time from the running event loop
        current_time = asyncio.get_running_loop().time()
        if _debug:
            COVDetection._debug("    - current_time: %r", current_time)

        # loop through the subscriptions and send out notifications
        for cov in notification_list:
            if _debug:
                COVDetection._debug("    - cov: %s", repr(cov))

            self._send_cov_notification(cov, list_of_values, current_time)

    def _send_cov_notification(self, cov, list_of_values, current_time=None) -> None:
        """
        Build a COV notification request for a subscription with the
        provided list of values and let the application send it.
        """
        if current_time is None:
            current_time = asyncio.get_running_loop().time()

        # calculate time remaining
        if not cov.cancel_handle:
            time_remaining = 0
        else:
            time_remaining = int(cov.cancel_handle.when() - current_time)

            # make sure it is at least one second
            if not time_remaining:
                time_remaining = 1

        # build a request with the correct type
        if cov.confirmed:
            request = ConfirmedCOVNotificationRequest()
        else:
            request = UnconfirmedCOVNotificationRequest()

        # find the device object
        device_object = None
        for obj in self.obj._app.objectIdentifier.values():
            if not isinstance(obj, DeviceObject):
                continue
            if device_object is not None:
                raise RuntimeError("duplicate device object")
            device_object = obj
        if device_object is None:
            raise RuntimeError("missing device object")

        # fill in the parameters
        request.pduDestination = cov.client_addr
        request.subscriberProcessIdentifier = cov.proc_id
        request.initiatingDeviceIdentifier = device_object.objectIdentifier
        request.monitoredObjectIdentifier = cov.obj_id
        request.timeRemaining = time_remaining
        request.listOfValues = list_of_values
        if _debug:
            COVDetection._debug("    - request: %s", repr(request))

        # let the application send it
        self.obj._app.cov_notification(cov, request)

    def _cov_property_change(self, key, old_value, new_value) -> None:
        """
        Monitor function installed on an object property while there are
        property-level subscriptions for it.  The change is offered to
        each of the subscriptions for the property (and optional array
        index), and each one applies its own COV criteria to decide if
        its subscriber should be notified.
        """
        prop_id, prop_index = key
        if _debug:
            COVDetection._debug(
                "_cov_property_change %r %r %r %r",
                key,
                prop_id,
                old_value,
                new_value,
            )

        # get the subscriptions for this property and array index
        property_subscriptions = self.cov_property_subscriptions.get(key, ())
        if not property_subscriptions:
            return

        if prop_index is None:
            old_element = old_value
            new_element = new_value
        else:
            old_element = self._property_element(old_value, prop_index)
            new_element = self._property_element(new_value, prop_index)

        for cov in list(property_subscriptions):
            if not self._cov_property_criteria(cov, old_element, new_element):
                if _debug:
                    COVDetection._debug("    - cov skipped: %r", cov)
                continue
            if _debug:
                COVDetection._debug("    - cov: %r", cov)

            self.send_property_cov_notifications(cov, new_element)

    @staticmethod
    def _property_element(value, prop_index: int):
        """Return an element of an array-like property value."""
        if value is None:
            return None
        try:
            return value[prop_index]
        except (TypeError, IndexError, KeyError):
            return None

    def _cov_property_criteria(self, cov, old_value, new_value) -> bool:
        """
        Apply the COV criteria for a property-level subscription.  For a
        numeric present-value the COV increment in the subscription is
        used, falling back to the object's cov-increment when the
        subscription didn't provide one.  Every other property notifies
        when the value is not equal to the previous one.
        """
        cov_increment = None
        if (cov.prop_id == "presentValue") and (
            "covIncrement" in self.obj._elements
        ):
            cov_increment = cov.covIncrement
            if cov_increment is None:
                cov_increment = self.obj.covIncrement

        if (cov_increment is not None) and isinstance(
            new_value, (int, float)
        ) and not isinstance(new_value, bool):
            last_value = cov.last_reported_value

            # first time around initialize to the old value
            if last_value is None:
                if _debug:
                    COVDetection._debug("    - first value: %r", new_value)
                cov.last_reported_value = new_value
                return True

            # see if it changed enough to trigger reporting
            value_changed = (
                new_value <= (last_value - cov_increment)
            ) or (new_value >= (last_value + cov_increment))
            if _debug:
                COVDetection._debug(
                    "    - value significantly changed: %r", value_changed
                )

            if value_changed:
                cov.last_reported_value = new_value
            return value_changed

        # everything else notifies on a simple inequality
        value_changed = old_value != new_value
        if _debug:
            COVDetection._debug("    - value changed: %r", value_changed)
        if value_changed:
            cov.last_reported_value = new_value
        return value_changed

    def send_property_cov_notifications(self, cov, property_value=None) -> None:
        """
        Send a COV notification to a property-level subscription with
        just the current value of its monitored property.
        """
        if _debug:
            COVDetection._debug(
                "send_property_cov_notifications %r %r", cov, property_value
            )

        # get the current value of the monitored property
        if property_value is None:
            property_value = getattr(self.obj, cov.prop_id)
            if _debug:
                COVDetection._debug(
                    "    - property_value: %r", property_value
                )
            if cov.prop_index is not None:
                property_value = self._property_element(
                    property_value, cov.prop_index
                )

        # this becomes the baseline for the next notification
        cov.last_reported_value = property_value

        # bundle it into a sequence
        list_of_values = [
            PropertyValue(
                propertyIdentifier=cov.prop_id,
                propertyArrayIndex=cov.prop_index,
                value=Any(property_value),
            )
        ]
        if _debug:
            COVDetection._debug("    - list_of_values: %r", list_of_values)

        # build and send the notification request
        self._send_cov_notification(cov, list_of_values)


class GenericCriteria(COVDetection):
    properties_tracked = (
        "presentValue",
        "statusFlags",
    )
    properties_reported = (
        "presentValue",
        "statusFlags",
    )
    monitored_property_reference = "presentValue"


@bacpypes_debugging
class COVIncrementCriteria(COVDetection):
    properties_tracked = (
        "presentValue",
        "statusFlags",
        "covIncrement",
    )
    properties_reported = (
        "presentValue",
        "statusFlags",
    )
    monitored_property_reference = "presentValue"

    def __init__(self, obj):
        if _debug:
            COVIncrementCriteria._debug("__init__ %r", obj)
        COVDetection.__init__(self, obj)

        # previously reported value
        self.previously_reported_value = None

    @monitor_filter("presentValue")
    def present_value_filter(self, old_value, new_value) -> bool:
        if _debug:
            COVIncrementCriteria._debug(
                "present_value_filter %r %r", old_value, new_value
            )

        # first time around initialize to the old value
        if self.previously_reported_value is None:
            if _debug:
                COVIncrementCriteria._debug("    - first value: %r", old_value)
            self.previously_reported_value = old_value

        # see if it changed enough to trigger reporting
        value_changed = (
            new_value <= (self.previously_reported_value - self.obj.covIncrement)
        ) or (new_value >= (self.previously_reported_value + self.obj.covIncrement))
        if _debug:
            COVIncrementCriteria._debug(
                "    - value significantly changed: %r", value_changed
            )

        return value_changed

    def send_cov_notifications(self, subscription=None):
        if _debug:
            COVIncrementCriteria._debug("send_cov_notifications %r", subscription)

        # when sending out notifications, keep the current value
        self.previously_reported_value = self.presentValue

        # continue
        super().send_cov_notifications(subscription)


class AccessDoorCriteria(COVDetection):
    properties_tracked = (
        "presentValue",
        "statusFlags",
        "doorAlarmState",
    )
    properties_reported = (
        "presentValue",
        "statusFlags",
        "doorAlarmState",
    )


class AccessPointCriteria(COVDetection):
    properties_tracked = (
        "accessEventTime",
        "statusFlags",
    )
    properties_reported = (
        "accessEvent",
        "statusFlags",
        "accessEventTag",
        "accessEventTime",
        "accessEventCredential",
        "accessEventAuthenticationFactor",
    )
    monitored_property_reference = "accessEvent"


class CredentialDataInputCriteria(COVDetection):
    properties_tracked = ("updateTime", "statusFlags")
    properties_reported = (
        "presentValue",
        "statusFlags",
        "updateTime",
    )


class LoadControlCriteria(COVDetection):
    properties_tracked = (
        "presentValue",
        "statusFlags",
        "requestedShedLevel",
        "startTime",
        "shedDuration",
        "dutyWindow",
    )
    properties_reported = (
        "presentValue",
        "statusFlags",
        "requestedShedLevel",
        "startTime",
        "shedDuration",
        "dutyWindow",
    )


@bacpypes_debugging
class PulseConverterCriteria(COVIncrementCriteria):
    properties_tracked = (
        "presentValue",
        "statusFlags",
        "covPeriod",
    )
    properties_reported = (
        "presentValue",
        "statusFlags",
    )

    def __init__(self, obj):
        if _debug:
            PulseConverterCriteria._debug("__init__ %r", obj)
        COVIncrementCriteria.__init__(self, obj)

        # check for a period
        if self.covPeriod == 0:
            if _debug:
                PulseConverterCriteria._debug("    - no periodic notifications")
            self.cov_period_task = None
        else:
            if _debug:
                PulseConverterCriteria._debug("    - covPeriod: %r", self.covPeriod)
            # self.cov_period_task = RecurringFunctionTask(
            #     self.covPeriod * 1000, self.send_cov_notifications
            # )
            if _debug:
                PulseConverterCriteria._debug("    - cov period task created")

    def add_subscription(self, cov):
        if _debug:
            PulseConverterCriteria._debug("add_subscription %r", cov)

        # let the parent classes do their thing
        COVIncrementCriteria.add_subscription(self, cov)

        # if there is a COV period task, install it
        if self.cov_period_task:
            self.cov_period_task.install_task()
            if _debug:
                PulseConverterCriteria._debug("    - cov period task installed")

    def cancel_subscription(self, cov):
        if _debug:
            PulseConverterCriteria._debug("cancel_subscription %r", cov)

        # let the parent classes do their thing
        COVIncrementCriteria.cancel_subscription(self, cov)

        # if there are no more subscriptions, cancel the task
        if not len(self.cov_subscriptions):
            if self.cov_period_task and self.cov_period_task.isScheduled:
                self.cov_period_task.suspend_task()
                if _debug:
                    PulseConverterCriteria._debug("    - cov period task suspended")
                self.cov_period_task = None

    @monitor_filter("covPeriod")
    def cov_period_filter(self, old_value, new_value) -> bool:
        if _debug:
            PulseConverterCriteria._debug(
                "cov_period_filter %r %r", old_value, new_value
            )

        # check for an old period
        if old_value != 0:
            if self.cov_period_task.isScheduled:
                self.cov_period_task.suspend_task()
                if _debug:
                    PulseConverterCriteria._debug("    - canceled old task")
            self.cov_period_task = None

        # check for a new period
        if new_value != 0:
            # self.cov_period_task = RecurringFunctionTask(
            #     new_value * 1000, self.send_cov_notifications
            # )
            self.cov_period_task.install_task()
            if _debug:
                PulseConverterCriteria._debug("    - new task created and installed")

        return False

    def send_cov_notifications(self, subscription=None):
        if _debug:
            PulseConverterCriteria._debug("send_cov_notifications %r", subscription)

        # pass along to the parent class as if something changed
        super().send_cov_notifications(subscription)


# mapping from object type to appropriate criteria class
criteria_type_map = {
    #   'accessDoor': GenericCriteria,  #TODO: needs AccessDoorCriteria
    "accessPoint": AccessPointCriteria,
    ObjectType.analogInput: COVIncrementCriteria,
    ObjectType.analogOutput: COVIncrementCriteria,
    ObjectType.analogValue: COVIncrementCriteria,
    "largeAnalogValue": COVIncrementCriteria,
    "integerValue": COVIncrementCriteria,
    "positiveIntegerValue": COVIncrementCriteria,
    "lightingOutput": COVIncrementCriteria,
    ObjectType.binaryInput: GenericCriteria,
    ObjectType.binaryOutput: GenericCriteria,
    ObjectType.binaryValue: GenericCriteria,
    "lifeSafetyPoint": GenericCriteria,
    "lifeSafetyZone": GenericCriteria,
    "multiStateInput": GenericCriteria,
    "multiStateOutput": GenericCriteria,
    "multiStateValue": GenericCriteria,
    "octetString": GenericCriteria,
    "characterString": GenericCriteria,
    "timeValue": GenericCriteria,
    "dateTimeValue": GenericCriteria,
    "dateValue": GenericCriteria,
    "timePatternValue": GenericCriteria,
    "datePatternValue": GenericCriteria,
    "dateTimePatternValue": GenericCriteria,
    "credentialDataInput": CredentialDataInputCriteria,
    "loadControl": LoadControlCriteria,
    "loop": GenericCriteria,
    "pulseConverter": PulseConverterCriteria,
}
