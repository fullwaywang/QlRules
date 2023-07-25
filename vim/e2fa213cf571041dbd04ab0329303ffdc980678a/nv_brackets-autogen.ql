/**
 * @name vim-e2fa213cf571041dbd04ab0329303ffdc980678a-nv_brackets
 * @id cpp/vim/e2fa213cf571041dbd04ab0329303ffdc980678a/nv-brackets
 * @description vim-e2fa213cf571041dbd04ab0329303ffdc980678a-src/normal.c-nv_brackets CVE-2022-1898
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vptr_4460, Variable vlen_4461, EqualityOperation target_3, AddressOfExpr target_4, ExprStmt target_5) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vptr_4460
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("vim_strnsave")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vptr_4460
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlen_4461
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(Variable vptr_4460, EqualityOperation target_3, ExprStmt target_5) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vptr_4460
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(ReturnStmt).toString() = "return ..."
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vptr_4460, EqualityOperation target_3, ExprStmt target_5) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("vim_free")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vptr_4460
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(3)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Variable vptr_4460, Variable vlen_4461, EqualityOperation target_3) {
		target_3.getAnOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_4461
		and target_3.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("find_ident_under_cursor")
		and target_3.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vptr_4460
		and target_3.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_3.getAnOperand().(Literal).getValue()="0"
}

predicate func_4(Variable vptr_4460, AddressOfExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vptr_4460
}

predicate func_5(Variable vptr_4460, Variable vlen_4461, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("find_pattern_in_path")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vptr_4460
		and target_5.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_4461
		and target_5.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="1"
		and target_5.getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="count0"
		and target_5.getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getThen().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="nchar"
		and target_5.getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_5.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="nchar"
		and target_5.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="15"
		and target_5.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getValue()="4"
		and target_5.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(Literal).getValue()="2"
		and target_5.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(Literal).getValue()="1"
		and target_5.getExpr().(FunctionCall).getArgument(6).(PointerFieldAccess).getTarget().getName()="count1"
		and target_5.getExpr().(FunctionCall).getArgument(7).(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_b_loc")
		and target_5.getExpr().(FunctionCall).getArgument(7).(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="nchar"
		and target_5.getExpr().(FunctionCall).getArgument(7).(ConditionalExpr).getThen().(Literal).getValue()="4"
		and target_5.getExpr().(FunctionCall).getArgument(7).(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="nchar"
		and target_5.getExpr().(FunctionCall).getArgument(7).(ConditionalExpr).getElse().(ConditionalExpr).getThen().(Literal).getValue()="1"
		and target_5.getExpr().(FunctionCall).getArgument(7).(ConditionalExpr).getElse().(ConditionalExpr).getElse().(Literal).getValue()="2"
		and target_5.getExpr().(FunctionCall).getArgument(8).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="cmdchar"
		and target_5.getExpr().(FunctionCall).getArgument(8).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="93"
		and target_5.getExpr().(FunctionCall).getArgument(8).(ConditionalExpr).getThen().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_5.getExpr().(FunctionCall).getArgument(8).(ConditionalExpr).getThen().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_5.getExpr().(FunctionCall).getArgument(8).(ConditionalExpr).getThen().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_5.getExpr().(FunctionCall).getArgument(8).(ConditionalExpr).getElse().(Literal).getValue()="1"
		and target_5.getExpr().(FunctionCall).getArgument(9).(Literal).getValue()="9223372036854775807"
}

from Function func, Variable vptr_4460, Variable vlen_4461, EqualityOperation target_3, AddressOfExpr target_4, ExprStmt target_5
where
not func_0(vptr_4460, vlen_4461, target_3, target_4, target_5)
and not func_1(vptr_4460, target_3, target_5)
and not func_2(vptr_4460, target_3, target_5)
and func_3(vptr_4460, vlen_4461, target_3)
and func_4(vptr_4460, target_4)
and func_5(vptr_4460, vlen_4461, target_5)
and vptr_4460.getType().hasName("char_u *")
and vlen_4461.getType().hasName("int")
and vptr_4460.getParentScope+() = func
and vlen_4461.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
