/**
 * @name linux-ec98ea7070e94cc25a422ec97d1421e28d97b7ee-iscsi_conn_get_addr_param
 * @id cpp/linux/ec98ea7070e94cc25a422ec97d1421e28d97b7ee/iscsi_conn_get_addr_param
 * @description linux-ec98ea7070e94cc25a422ec97d1421e28d97b7ee-iscsi_conn_get_addr_param 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_3562, Variable vsin_3565) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("sprintf")
		and not target_0.getTarget().hasName("sysfs_emit")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vbuf_3562
		and target_0.getArgument(1).(StringLiteral).getValue()="%pI4\n"
		and target_0.getArgument(2).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="s_addr"
		and target_0.getArgument(2).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sin_addr"
		and target_0.getArgument(2).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsin_3565)
}

predicate func_1(Parameter vbuf_3562, Variable vsin6_3564) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("sprintf")
		and not target_1.getTarget().hasName("sysfs_emit")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vbuf_3562
		and target_1.getArgument(1).(StringLiteral).getValue()="%pI6\n"
		and target_1.getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sin6_addr"
		and target_1.getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsin6_3564)
}

predicate func_2(Parameter vbuf_3562, Variable vsin_3565) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("sprintf")
		and not target_2.getTarget().hasName("sysfs_emit")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vbuf_3562
		and target_2.getArgument(1).(StringLiteral).getValue()="%hu\n"
		and target_2.getArgument(2).(FunctionCall).getTarget().hasName("__builtin_bswap16")
		and target_2.getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sin_port"
		and target_2.getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsin_3565)
}

predicate func_3(Parameter vbuf_3562, Variable vsin6_3564) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("sprintf")
		and not target_3.getTarget().hasName("sysfs_emit")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vbuf_3562
		and target_3.getArgument(1).(StringLiteral).getValue()="%hu\n"
		and target_3.getArgument(2).(FunctionCall).getTarget().hasName("__builtin_bswap16")
		and target_3.getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sin6_port"
		and target_3.getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsin6_3564)
}

from Function func, Parameter vbuf_3562, Variable vsin6_3564, Variable vsin_3565
where
func_0(vbuf_3562, vsin_3565)
and func_1(vbuf_3562, vsin6_3564)
and func_2(vbuf_3562, vsin_3565)
and func_3(vbuf_3562, vsin6_3564)
and vbuf_3562.getType().hasName("char *")
and vsin6_3564.getType().hasName("sockaddr_in6 *")
and vsin_3565.getType().hasName("sockaddr_in *")
and vbuf_3562.getParentScope+() = func
and vsin6_3564.getParentScope+() = func
and vsin_3565.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
