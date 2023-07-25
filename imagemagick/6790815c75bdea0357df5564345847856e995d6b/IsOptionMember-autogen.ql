/**
 * @name imagemagick-6790815c75bdea0357df5564345847856e995d6b-IsOptionMember
 * @id cpp/imagemagick/6790815c75bdea0357df5564345847856e995d6b/IsOptionMember
 * @description imagemagick-6790815c75bdea0357df5564345847856e995d6b-MagickCore/option.c-IsOptionMember CVE-2016-10252
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable voption_list_2405, EqualityOperation target_1, LogicalAndExpr target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=voption_list_2405
		and target_0.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyString")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=voption_list_2405
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_0)
		and target_1.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_1(Variable voption_list_2405, EqualityOperation target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget()=voption_list_2405
		and target_1.getAnOperand().(Literal).getValue()="0"
}

predicate func_2(Variable voption_list_2405, LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=voption_list_2405
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="33"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("LocaleCompare")
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=voption_list_2405
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable voption_list_2405, EqualityOperation target_1, LogicalAndExpr target_2
where
not func_0(voption_list_2405, target_1, target_2, func)
and func_1(voption_list_2405, target_1)
and func_2(voption_list_2405, target_2)
and voption_list_2405.getType().hasName("char **")
and voption_list_2405.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
