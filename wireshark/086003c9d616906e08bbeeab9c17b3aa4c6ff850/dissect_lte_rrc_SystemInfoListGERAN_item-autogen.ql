/**
 * @name wireshark-086003c9d616906e08bbeeab9c17b3aa4c6ff850-dissect_lte_rrc_SystemInfoListGERAN_item
 * @id cpp/wireshark/086003c9d616906e08bbeeab9c17b3aa4c6ff850/dissect-lte-rrc-SystemInfoListGERAN-item
 * @description wireshark-086003c9d616906e08bbeeab9c17b3aa4c6ff850-epan/dissectors/packet-lte-rrc.c-dissect_lte_rrc_SystemInfoListGERAN_item CVE-2020-9431
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpd_52280, FunctionCall target_0) {
		target_0.getTarget().hasName("tvb_new_real_data")
		and not target_0.getTarget().hasName("tvb_new_child_real_data")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vpd_52280
		and target_0.getArgument(1).(Literal).getValue()="1"
		and target_0.getArgument(2).(Literal).getValue()="1"
}

predicate func_1(Variable vpd_52293, FunctionCall target_1) {
		target_1.getTarget().hasName("tvb_new_real_data")
		and not target_1.getTarget().hasName("tvb_new_child_real_data")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vpd_52293
		and target_1.getArgument(1).(Literal).getValue()="1"
		and target_1.getArgument(2).(Literal).getValue()="1"
}

from Function func, Variable vpd_52280, Variable vpd_52293, FunctionCall target_0, FunctionCall target_1
where
func_0(vpd_52280, target_0)
and func_1(vpd_52293, target_1)
and vpd_52280.getType().hasName("guint8 *")
and vpd_52293.getType().hasName("guint8 *")
and vpd_52280.getParentScope+() = func
and vpd_52293.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
