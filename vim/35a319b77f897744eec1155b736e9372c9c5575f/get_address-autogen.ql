/**
 * @name vim-35a319b77f897744eec1155b736e9372c9c5575f-get_address
 * @id cpp/vim/35a319b77f897744eec1155b736e9372c9c5575f/get-address
 * @description vim-35a319b77f897744eec1155b736e9372c9c5575f-src/ex_docmd.c-get_address CVE-2021-3875
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlnum_4070, ExprStmt target_4, EqualityOperation target_2) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlnum_4070
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlnum_4070
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="9223372036854775807"
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vlnum_4070, Variable vcurbuf, EqualityOperation target_2, ExprStmt target_4, ExprStmt target_5, EqualityOperation target_6) {
	exists(ConditionalExpr target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlnum_4070
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="ml_line_count"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_ml"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
		and target_1.getThen().(ValueFieldAccess).getTarget().getName()="ml_line_count"
		and target_1.getThen().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_ml"
		and target_1.getThen().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
		and target_1.getElse().(VariableAccess).getTarget()=vlnum_4070
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_1.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_2.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_2(Variable vlnum_4070, ExprStmt target_4, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vlnum_4070
		and target_2.getAnOperand().(Literal).getValue()="9223372036854775807"
		and target_2.getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Variable vlnum_4070, VariableAccess target_3) {
		target_3.getTarget()=vlnum_4070
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_3.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
}

predicate func_4(Variable vlnum_4070, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlnum_4070
}

predicate func_5(Variable vlnum_4070, Variable vcurbuf, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlnum_4070
		and target_5.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="ml_line_count"
		and target_5.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_ml"
		and target_5.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
}

predicate func_6(Variable vcurbuf, EqualityOperation target_6) {
		target_6.getAnOperand().(FunctionCall).getTarget().hasName("searchit")
		and target_6.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcurbuf
		and target_6.getAnOperand().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_6.getAnOperand().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="63"
		and target_6.getAnOperand().(FunctionCall).getArgument(4).(ConditionalExpr).getThen().(UnaryMinusExpr).getValue()="-1"
		and target_6.getAnOperand().(FunctionCall).getArgument(4).(ConditionalExpr).getElse().(Literal).getValue()="1"
		and target_6.getAnOperand().(FunctionCall).getArgument(5).(StringLiteral).getValue()=""
		and target_6.getAnOperand().(FunctionCall).getArgument(6).(Literal).getValue()="1"
		and target_6.getAnOperand().(FunctionCall).getArgument(7).(Literal).getValue()="12"
		and target_6.getAnOperand().(FunctionCall).getArgument(9).(Literal).getValue()="0"
		and target_6.getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable vlnum_4070, Variable vcurbuf, EqualityOperation target_2, VariableAccess target_3, ExprStmt target_4, ExprStmt target_5, EqualityOperation target_6
where
not func_0(vlnum_4070, target_4, target_2)
and not func_1(vlnum_4070, vcurbuf, target_2, target_4, target_5, target_6)
and func_2(vlnum_4070, target_4, target_2)
and func_3(vlnum_4070, target_3)
and func_4(vlnum_4070, target_4)
and func_5(vlnum_4070, vcurbuf, target_5)
and func_6(vcurbuf, target_6)
and vlnum_4070.getType().hasName("linenr_T")
and vcurbuf.getType().hasName("buf_T *")
and vlnum_4070.getParentScope+() = func
and not vcurbuf.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
