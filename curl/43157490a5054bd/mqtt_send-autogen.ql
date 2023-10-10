/**
 * @name curl-43157490a5054bd-mqtt_send
 * @id cpp/curl/43157490a5054bd/mqtt-send
 * @description curl-43157490a5054bd-mqtt_send CVE-2021-22945
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlen_113, Variable vmq_118, Variable vn_119) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sendleftovers"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmq_118
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlen_113
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vn_119)
}

predicate func_1(Parameter vlen_113, Variable vmq_118, Variable vn_119) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nsend"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmq_118
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlen_113
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vn_119)
}

predicate func_2(Variable vmq_118) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="nsend"
		and target_2.getQualifier().(VariableAccess).getTarget()=vmq_118)
}

from Function func, Parameter vlen_113, Variable vmq_118, Variable vn_119
where
not func_0(vlen_113, vmq_118, vn_119)
and not func_1(vlen_113, vmq_118, vn_119)
and vlen_113.getType().hasName("size_t")
and vmq_118.getType().hasName("MQTT *")
and func_2(vmq_118)
and vn_119.getType().hasName("ssize_t")
and vlen_113.getParentScope+() = func
and vmq_118.getParentScope+() = func
and vn_119.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
