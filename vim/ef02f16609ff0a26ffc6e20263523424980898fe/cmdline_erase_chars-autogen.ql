/**
 * @name vim-ef02f16609ff0a26ffc6e20263523424980898fe-cmdline_erase_chars
 * @id cpp/vim/ef02f16609ff0a26ffc6e20263523424980898fe/cmdline-erase-chars
 * @description vim-ef02f16609ff0a26ffc6e20263523424980898fe-src/ex_getln.c-cmdline_erase_chars CVE-2022-1619
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vccline, Variable vp_1063, EqualityOperation target_3, LogicalAndExpr target_4, LogicalAndExpr target_5, ExprStmt target_6, ArrayExpr target_7) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vp_1063
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="cmdbuff"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vccline
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof WhileStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getExpr().(PrefixDecrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_7.getArrayBase().(VariableAccess).getLocation()))
}

predicate func_1(Variable vi_1046, Variable vp_1063, EqualityOperation target_3, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_1046
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("vim_iswordc")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_1063
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getValue()="-1"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_2(Variable vi_1046, Variable vccline, Variable vp_1063, EqualityOperation target_3, WhileStmt target_2) {
		target_2.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vp_1063
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="cmdbuff"
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vccline
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("vim_isspace")
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_1063
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("vim_iswordc")
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_1063
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getValue()="-1"
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vi_1046
		and target_2.getStmt().(ExprStmt).getExpr().(PrefixDecrExpr).getOperand().(VariableAccess).getTarget()=vp_1063
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_3(EqualityOperation target_3) {
		target_3.getAnOperand().(Literal).getValue()="23"
}

predicate func_4(Variable vccline, Variable vp_1063, LogicalAndExpr target_4) {
		target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vp_1063
		and target_4.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="cmdbuff"
		and target_4.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vccline
		and target_4.getAnOperand().(FunctionCall).getTarget().hasName("vim_isspace")
		and target_4.getAnOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_1063
		and target_4.getAnOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getValue()="-1"
}

predicate func_5(Variable vi_1046, Variable vccline, Variable vp_1063, LogicalAndExpr target_5) {
		target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vp_1063
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="cmdbuff"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vccline
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("vim_isspace")
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_1063
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getValue()="-1"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("vim_iswordc")
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_1063
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getValue()="-1"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vi_1046
}

predicate func_6(Variable vp_1063, ExprStmt target_6) {
		target_6.getExpr().(PrefixDecrExpr).getOperand().(VariableAccess).getTarget()=vp_1063
}

predicate func_7(Variable vp_1063, ArrayExpr target_7) {
		target_7.getArrayBase().(VariableAccess).getTarget()=vp_1063
		and target_7.getArrayOffset().(UnaryMinusExpr).getValue()="-1"
}

from Function func, Variable vi_1046, Variable vccline, Variable vp_1063, ExprStmt target_1, WhileStmt target_2, EqualityOperation target_3, LogicalAndExpr target_4, LogicalAndExpr target_5, ExprStmt target_6, ArrayExpr target_7
where
not func_0(vccline, vp_1063, target_3, target_4, target_5, target_6, target_7)
and func_1(vi_1046, vp_1063, target_3, target_1)
and func_2(vi_1046, vccline, vp_1063, target_3, target_2)
and func_3(target_3)
and func_4(vccline, vp_1063, target_4)
and func_5(vi_1046, vccline, vp_1063, target_5)
and func_6(vp_1063, target_6)
and func_7(vp_1063, target_7)
and vi_1046.getType().hasName("int")
and vccline.getType().hasName("cmdline_info_T")
and vp_1063.getType().hasName("char_u *")
and vi_1046.getParentScope+() = func
and not vccline.getParentScope+() = func
and vp_1063.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
