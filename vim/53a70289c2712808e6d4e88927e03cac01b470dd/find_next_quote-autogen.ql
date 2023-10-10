/**
 * @name vim-53a70289c2712808e6d4e88927e03cac01b470dd-find_next_quote
 * @id cpp/vim/53a70289c2712808e6d4e88927e03cac01b470dd/find-next-quote
 * @description vim-53a70289c2712808e6d4e88927e03cac01b470dd-src/textobject.c-find_next_quote CVE-2022-1629
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vline_1654, Parameter vcol_1655, LogicalAndExpr target_2, ExprStmt target_3, PointerArithmeticOperation target_4, ExprStmt target_1) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vline_1654
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcol_1655
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_1.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vcol_1655, EqualityOperation target_5, ExprStmt target_1) {
		target_1.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vcol_1655
		and target_1.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_2(LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(FunctionCall).getTarget().hasName("vim_strchr")
}

predicate func_3(Parameter vline_1654, Parameter vcol_1655, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vline_1654
		and target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcol_1655
}

predicate func_4(Parameter vline_1654, Parameter vcol_1655, PointerArithmeticOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vline_1654
		and target_4.getAnOperand().(VariableAccess).getTarget()=vcol_1655
}

predicate func_5(EqualityOperation target_5) {
		target_5.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vline_1654, Parameter vcol_1655, ExprStmt target_1, LogicalAndExpr target_2, ExprStmt target_3, PointerArithmeticOperation target_4, EqualityOperation target_5
where
not func_0(vline_1654, vcol_1655, target_2, target_3, target_4, target_1)
and func_1(vcol_1655, target_5, target_1)
and func_2(target_2)
and func_3(vline_1654, vcol_1655, target_3)
and func_4(vline_1654, vcol_1655, target_4)
and func_5(target_5)
and vline_1654.getType().hasName("char_u *")
and vcol_1655.getType().hasName("int")
and vline_1654.getParentScope+() = func
and vcol_1655.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
