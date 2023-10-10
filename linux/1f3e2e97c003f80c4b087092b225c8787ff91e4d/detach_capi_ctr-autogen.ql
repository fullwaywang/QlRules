/**
 * @name linux-1f3e2e97c003f80c4b087092b225c8787ff91e4d-detach_capi_ctr
 * @id cpp/linux/1f3e2e97c003f80c4b087092b225c8787ff91e4d/detach_capi_ctr
 * @description linux-1f3e2e97c003f80c4b087092b225c8787ff91e4d-detach_capi_ctr 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vctr_475, Variable verr_477, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="cnr"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctr_475
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="cnr"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctr_475
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="32"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_477
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and target_0.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0))
}

predicate func_3(Parameter vctr_475) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("ctr_down")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vctr_475)
}

from Function func, Parameter vctr_475, Variable verr_477
where
not func_0(vctr_475, verr_477, func)
and vctr_475.getType().hasName("capi_ctr *")
and func_3(vctr_475)
and verr_477.getType().hasName("int")
and vctr_475.getParentScope+() = func
and verr_477.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
