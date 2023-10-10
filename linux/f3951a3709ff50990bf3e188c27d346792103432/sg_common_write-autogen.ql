/**
 * @name linux-f3951a3709ff50990bf3e188c27d346792103432-sg_common_write
 * @id cpp/linux/f3951a3709ff50990bf3e188c27d346792103432/sg_common_write
 * @description linux-f3951a3709ff50990bf3e188c27d346792103432-sg_common_write 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vsrp_763) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="cmd"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rq"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrp_763
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="__cmd"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rq"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrp_763
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cmd"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rq"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrp_763
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="bio"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrp_763)
}

predicate func_1(Parameter vsrp_763) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rq"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrp_763
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="bio"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrp_763)
}

predicate func_2(Parameter vsrp_763) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("blk_end_request_all")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="rq"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrp_763
		and target_2.getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-5"
		and target_2.getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getOperand().(Literal).getValue()="5"
		and target_2.getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="bio"
		and target_2.getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrp_763)
}

predicate func_3(Parameter vsrp_763) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="bio"
		and target_3.getQualifier().(VariableAccess).getTarget()=vsrp_763)
}

from Function func, Parameter vsrp_763
where
not func_0(vsrp_763)
and not func_1(vsrp_763)
and func_2(vsrp_763)
and vsrp_763.getType().hasName("Sg_request *")
and func_3(vsrp_763)
and vsrp_763.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
