/**
 * @name coturn-170da1140797748ae85565b5a93a2e35e7b07b6a-new_blist_elem
 * @id cpp/coturn/170da1140797748ae85565b5a93a2e35e7b07b6a/new-blist-elem
 * @description coturn-170da1140797748ae85565b5a93a2e35e7b07b6a-src/apps/relay/ns_ioalib_engine_impl.c-new_blist_elem CVE-2020-4067
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vret_292, NotExpr target_10, ExprStmt target_9) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vret_292
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("turn_log_func_default")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s: Cannot allocate memory for STUN buffer!\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("const char[15]")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_1(Function func) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("turn_log_func_default")
		and target_1.getArgument(1).(StringLiteral).getValue()="%s: Cannot allocate memory for STUN buffer!\n"
		and target_1.getArgument(2).(VariableAccess).getType().hasName("const char[15]")
		and target_1.getEnclosingFunction() = func)
}

*/
predicate func_2(Variable vret_292, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(VariableAccess).getTarget()=vret_292
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("bzero")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="buf"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_292
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="65528"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_2))
}

/*predicate func_3(Variable vret_292, ExprStmt target_14) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("bzero")
		and target_3.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="buf"
		and target_3.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_292
		and target_3.getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getArgument(1).(SizeofTypeOperator).getValue()="65528"
		and target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_4(Variable vret_292, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="buf"
		and target_4.getQualifier().(VariableAccess).getTarget()=vret_292
}

predicate func_5(Variable vret_292, VariableAccess target_5) {
		target_5.getTarget()=vret_292
}

predicate func_6(Variable vret_292, VariableAccess target_6) {
		target_6.getTarget()=vret_292
}

predicate func_7(Variable vret_292, AssignExpr target_7) {
		target_7.getLValue().(ValueFieldAccess).getTarget().getName()="len"
		and target_7.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="buf"
		and target_7.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_292
		and target_7.getRValue().(Literal).getValue()="0"
}

predicate func_8(Variable vret_292, AssignExpr target_8) {
		target_8.getLValue().(ValueFieldAccess).getTarget().getName()="offset"
		and target_8.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="buf"
		and target_8.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_292
		and target_8.getRValue().(Literal).getValue()="0"
}

predicate func_9(Variable vret_292, NotExpr target_10, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="coffset"
		and target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="buf"
		and target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_292
		and target_9.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
}

predicate func_10(Variable vret_292, NotExpr target_10) {
		target_10.getOperand().(VariableAccess).getTarget()=vret_292
}

predicate func_14(Variable vret_292, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_292
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("malloc")
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(SizeofTypeOperator).getType() instanceof LongType
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(SizeofTypeOperator).getValue()="65536"
}

from Function func, Variable vret_292, PointerFieldAccess target_4, VariableAccess target_5, VariableAccess target_6, AssignExpr target_7, AssignExpr target_8, ExprStmt target_9, NotExpr target_10, ExprStmt target_14
where
not func_0(vret_292, target_10, target_9)
and not func_2(vret_292, func)
and func_4(vret_292, target_4)
and func_5(vret_292, target_5)
and func_6(vret_292, target_6)
and func_7(vret_292, target_7)
and func_8(vret_292, target_8)
and func_9(vret_292, target_10, target_9)
and func_10(vret_292, target_10)
and func_14(vret_292, target_14)
and vret_292.getType().hasName("stun_buffer_list_elem *")
and vret_292.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
