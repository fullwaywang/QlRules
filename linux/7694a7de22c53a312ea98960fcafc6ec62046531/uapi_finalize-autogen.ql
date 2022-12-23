/**
 * @name linux-7694a7de22c53a312ea98960fcafc6ec62046531-uapi_finalize
 * @id cpp/linux/7694a7de22c53a312ea98960fcafc6ec62046531/uapi_finalize
 * @description linux-7694a7de22c53a312ea98960fcafc6ec62046531-uapi_finalize 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vdata_417, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vdata_417
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="12"
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_0))
}

predicate func_1(Variable vdata_417, Parameter vuapi_415) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=vdata_417
		and target_1.getRValue().(FunctionCall).getTarget().hasName("kmalloc_array")
		and target_1.getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="num_write"
		and target_1.getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vuapi_415
		and target_1.getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="num_write_ex"
		and target_1.getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vuapi_415
		and target_1.getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="8"
		and target_1.getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="write_methods"
		and target_1.getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vuapi_415
		and target_1.getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getValue()="3264"
		and target_1.getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="3136"
		and target_1.getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="1024"
		and target_1.getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="2048"
		and target_1.getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="64"
		and target_1.getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="128")
}

from Function func, Variable vdata_417, Parameter vuapi_415
where
not func_0(vdata_417, func)
and vdata_417.getType().hasName("const uverbs_api_write_method **")
and func_1(vdata_417, vuapi_415)
and vuapi_415.getType().hasName("uverbs_api *")
and vdata_417.getParentScope+() = func
and vuapi_415.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
