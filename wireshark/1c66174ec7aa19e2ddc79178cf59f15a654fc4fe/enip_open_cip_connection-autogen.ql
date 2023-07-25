/**
 * @name wireshark-1c66174ec7aa19e2ddc79178cf59f15a654fc4fe-enip_open_cip_connection
 * @id cpp/wireshark/1c66174ec7aa19e2ddc79178cf59f15a654fc4fe/enip-open-cip-connection
 * @description wireshark-1c66174ec7aa19e2ddc79178cf59f15a654fc4fe-epan/dissectors/packet-enip.c-enip_open_cip_connection CVE-2019-5721
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpinfo_1034, Parameter vconnInfo_1034, FunctionCall target_0) {
		target_0.getTarget().hasName("copy_address_shallow")
		and not target_0.getTarget().hasName("copy_address_wmem")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="ipaddress"
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="O2T"
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnInfo_1034
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="src"
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpinfo_1034
}

predicate func_1(Parameter vpinfo_1034, Parameter vconnInfo_1034, FunctionCall target_1) {
		target_1.getTarget().hasName("copy_address_shallow")
		and not target_1.getTarget().hasName("copy_address_wmem")
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="ipaddress"
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="T2O"
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnInfo_1034
		and target_1.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dst"
		and target_1.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpinfo_1034
}

from Function func, Parameter vpinfo_1034, Parameter vconnInfo_1034, FunctionCall target_0, FunctionCall target_1
where
func_0(vpinfo_1034, vconnInfo_1034, target_0)
and func_1(vpinfo_1034, vconnInfo_1034, target_1)
and vpinfo_1034.getType().hasName("packet_info *")
and vconnInfo_1034.getType().hasName("cip_conn_info_t *")
and vpinfo_1034.getParentScope+() = func
and vconnInfo_1034.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
