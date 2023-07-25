/**
 * @name openvpn-37bc691e7d26ea4eb61a8a434ebd7a9ae76225ab-multi_process_incoming_link
 * @id cpp/openvpn/37bc691e7d26ea4eb61a8a434ebd7a9ae76225ab/multi-process-incoming-link
 * @description openvpn-37bc691e7d26ea4eb61a8a434ebd7a9ae76225ab-src/openvpn/multi.c-multi_process_incoming_link CVE-2020-11810
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vc_2525, Variable vfloated_2530, BlockStmt target_2, FunctionCall target_3, ExprStmt target_4) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vfloated_2530
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="len"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="buf"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="c2"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_2525
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vfloated_2530, BlockStmt target_2, VariableAccess target_1) {
		target_1.getTarget()=vfloated_2530
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("multi_process_float")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="pending"
}

predicate func_3(Variable vc_2525, Variable vfloated_2530, FunctionCall target_3) {
		target_3.getTarget().hasName("process_incoming_link_part1")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vc_2525
		and target_3.getArgument(2).(VariableAccess).getTarget()=vfloated_2530
}

predicate func_4(Variable vc_2525, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("process_incoming_link_part2")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_2525
}

from Function func, Variable vc_2525, Variable vfloated_2530, VariableAccess target_1, BlockStmt target_2, FunctionCall target_3, ExprStmt target_4
where
not func_0(vc_2525, vfloated_2530, target_2, target_3, target_4)
and func_1(vfloated_2530, target_2, target_1)
and func_2(target_2)
and func_3(vc_2525, vfloated_2530, target_3)
and func_4(vc_2525, target_4)
and vc_2525.getType().hasName("context *")
and vfloated_2530.getType().hasName("bool")
and vc_2525.getParentScope+() = func
and vfloated_2530.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
