/**
 * @name vim-35d21c6830fc2d68aca838424a0e786821c5891c-do_cmdline
 * @id cpp/vim/35d21c6830fc2d68aca838424a0e786821c5891c/do-cmdline
 * @description vim-35d21c6830fc2d68aca838424a0e786821c5891c-src/ex_docmd.c-do_cmdline CVE-2022-3099
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlines_ga_635, Variable vcurrent_line_636, BlockStmt target_2, AddressOfExpr target_3, ArrayExpr target_4, ExprStmt target_5) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="ga_len"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vlines_ga_635
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcurrent_line_636
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getArrayBase().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vbreakpoint_639, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget()=vbreakpoint_639
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vbreakpoint_639, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbreakpoint_639
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("dbg_find_breakpoint")
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("getline_equal")
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_3(Variable vlines_ga_635, AddressOfExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vlines_ga_635
}

predicate func_4(Variable vlines_ga_635, Variable vcurrent_line_636, ArrayExpr target_4) {
		target_4.getArrayBase().(ValueFieldAccess).getTarget().getName()="ga_data"
		and target_4.getArrayBase().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vlines_ga_635
		and target_4.getArrayOffset().(VariableAccess).getTarget()=vcurrent_line_636
}

predicate func_5(Variable vcurrent_line_636, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcurrent_line_636
		and target_5.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="cs_line"
		and target_5.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(ValueFieldAccess).getTarget().getName()="cs_idx"
}

from Function func, Variable vlines_ga_635, Variable vcurrent_line_636, Variable vbreakpoint_639, EqualityOperation target_1, BlockStmt target_2, AddressOfExpr target_3, ArrayExpr target_4, ExprStmt target_5
where
not func_0(vlines_ga_635, vcurrent_line_636, target_2, target_3, target_4, target_5)
and func_1(vbreakpoint_639, target_2, target_1)
and func_2(vbreakpoint_639, target_2)
and func_3(vlines_ga_635, target_3)
and func_4(vlines_ga_635, vcurrent_line_636, target_4)
and func_5(vcurrent_line_636, target_5)
and vlines_ga_635.getType().hasName("garray_T")
and vcurrent_line_636.getType().hasName("int")
and vbreakpoint_639.getType().hasName("linenr_T *")
and vlines_ga_635.getParentScope+() = func
and vcurrent_line_636.getParentScope+() = func
and vbreakpoint_639.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
