/**
 * @name varnish-2d8fc1a784a1e26d78c30174923a2b14ee2ebf62-SES_Wait
 * @id cpp/varnish/2d8fc1a784a1e26d78c30174923a2b14ee2ebf62/SES-Wait
 * @description varnish-2d8fc1a784a1e26d78c30174923a2b14ee2ebf62-bin/varnishd/cache/cache_session.c-SES_Wait CVE-2020-11653
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, SizeofTypeOperator target_0) {
		target_0.getType() instanceof LongType
		and target_0.getValue()="56"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("unsigned int")
		and target_1.getExpr().(AssignExpr).getRValue() instanceof SizeofTypeOperator
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_1))
}

predicate func_2(BlockStmt target_8, Function func) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_2.getGreaterOperand().(SizeofTypeOperator).getValue()="32"
		and target_2.getLesserOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_2.getParent().(IfStmt).getThen()=target_8
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(RelationalOperation target_7, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("unsigned int")
		and target_3.getExpr().(AssignExpr).getRValue().(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getExpr().(AssignExpr).getRValue().(SizeofTypeOperator).getValue()="32"
		and target_3.getParent().(IfStmt).getCondition()=target_7
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Parameter vsp_453, ExprStmt target_9, ExprStmt target_10, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("WS_ReserveSize")
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ws"
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_453
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("unsigned int")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SES_Delete")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsp_453
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("__builtin_nanf")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getValue()="NaN"
		and target_4.getThen().(BlockStmt).getStmt(1).(ReturnStmt).toString() = "return ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_4)
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(Function func, SizeofTypeOperator target_6) {
		target_6.getType() instanceof LongType
		and target_6.getValue()="56"
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Parameter vsp_453, BlockStmt target_8, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getLesserOperand().(FunctionCall).getTarget().hasName("WS_ReserveSize")
		and target_7.getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ws"
		and target_7.getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_453
		and target_7.getLesserOperand().(FunctionCall).getArgument(1) instanceof SizeofTypeOperator
		and target_7.getGreaterOperand() instanceof SizeofTypeOperator
		and target_7.getParent().(IfStmt).getThen()=target_8
}

predicate func_8(Parameter vsp_453, BlockStmt target_8) {
		target_8.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SES_Delete")
		and target_8.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsp_453
		and target_8.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("__builtin_nanf")
		and target_8.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getValue()="NaN"
		and target_8.getStmt(1).(ReturnStmt).toString() = "return ..."
}

predicate func_9(Parameter vsp_453, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("VTCP_nonblocking")
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="fd"
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_453
}

predicate func_10(Parameter vsp_453, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="f"
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ws"
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_453
}

from Function func, Parameter vsp_453, SizeofTypeOperator target_0, SizeofTypeOperator target_6, RelationalOperation target_7, BlockStmt target_8, ExprStmt target_9, ExprStmt target_10
where
func_0(func, target_0)
and not func_1(func)
and not func_2(target_8, func)
and not func_3(target_7, func)
and not func_4(vsp_453, target_9, target_10, func)
and func_6(func, target_6)
and func_7(vsp_453, target_8, target_7)
and func_8(vsp_453, target_8)
and func_9(vsp_453, target_9)
and func_10(vsp_453, target_10)
and vsp_453.getType().hasName("sess *")
and vsp_453.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
