/**
 * @name vim-1c73b65229c25e3c1fd8824ba958f7cc4d604f9c-do_put
 * @id cpp/vim/1c73b65229c25e3c1fd8824ba958f7cc4d604f9c/do-put
 * @description vim-1c73b65229c25e3c1fd8824ba958f7cc4d604f9c-src/register.c-do_put CVE-2023-1170
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vspaces_1824, BlockStmt target_3, ExprStmt target_4, ExprStmt target_5) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=vspaces_1824
		and target_0.getLesserOperand().(Literal).getValue()="0"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vspaces_1824
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_3
		and target_4.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(Variable vcur_ve_flags_1564, Variable vcurwin, LogicalAndExpr target_6, ExprStmt target_7, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="col"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcur_ve_flags_1564
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="coladd"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="col"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(VariableAccess).getType().hasName("int")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="col"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(53)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(53).getFollowingStmt()=target_1)
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vspaces_1824, BlockStmt target_3, VariableAccess target_2) {
		target_2.getTarget()=vspaces_1824
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_3
}

predicate func_3(Variable vspaces_1824, BlockStmt target_3) {
		target_3.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_3.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="32"
		and target_3.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vspaces_1824
		and target_3.getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vspaces_1824
}

predicate func_4(Variable vspaces_1824, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vspaces_1824
		and target_4.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="startspaces"
		and target_4.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="endspaces"
}

predicate func_5(Variable vspaces_1824, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_5.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="32"
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vspaces_1824
}

predicate func_6(Variable vcur_ve_flags_1564, Variable vcurwin, LogicalAndExpr target_6) {
		target_6.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcur_ve_flags_1564
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="coladd"
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="col"
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
}

predicate func_7(Variable vcurwin, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="w_set_curswant"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_7.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

from Function func, Variable vcur_ve_flags_1564, Variable vcurwin, Variable vspaces_1824, VariableAccess target_2, BlockStmt target_3, ExprStmt target_4, ExprStmt target_5, LogicalAndExpr target_6, ExprStmt target_7
where
not func_0(vspaces_1824, target_3, target_4, target_5)
and not func_1(vcur_ve_flags_1564, vcurwin, target_6, target_7, func)
and func_2(vspaces_1824, target_3, target_2)
and func_3(vspaces_1824, target_3)
and func_4(vspaces_1824, target_4)
and func_5(vspaces_1824, target_5)
and func_6(vcur_ve_flags_1564, vcurwin, target_6)
and func_7(vcurwin, target_7)
and vcur_ve_flags_1564.getType().hasName("unsigned int")
and vcurwin.getType().hasName("win_T *")
and vspaces_1824.getType().hasName("int")
and vcur_ve_flags_1564.getParentScope+() = func
and not vcurwin.getParentScope+() = func
and vspaces_1824.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
