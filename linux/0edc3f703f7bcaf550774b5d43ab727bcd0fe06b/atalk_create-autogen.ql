/**
 * @name linux-0edc3f703f7bcaf550774b5d43ab727bcd0fe06b-atalk_create
 * @id cpp/linux/0edc3f703f7bcaf550774b5d43ab727bcd0fe06b/atalk-create
 * @description linux-0edc3f703f7bcaf550774b5d43ab727bcd0fe06b-atalk_create 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrc_1015, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_1015
		and target_0.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-1"
		and target_0.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vsock_1011, Parameter vkern_1012, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsock_1011
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vkern_1012
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("capable")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(Literal).getValue()="13"
		and target_1.getThen().(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vsock_1011) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="type"
		and target_2.getQualifier().(VariableAccess).getTarget()=vsock_1011)
}

from Function func, Parameter vsock_1011, Parameter vkern_1012, Variable vrc_1015
where
not func_0(vrc_1015, func)
and not func_1(vsock_1011, vkern_1012, func)
and vsock_1011.getType().hasName("socket *")
and func_2(vsock_1011)
and vkern_1012.getType().hasName("int")
and vrc_1015.getType().hasName("int")
and vsock_1011.getParentScope+() = func
and vkern_1012.getParentScope+() = func
and vrc_1015.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
