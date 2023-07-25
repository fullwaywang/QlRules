/**
 * @name vim-caea66442d86e7bbba3bf3dc202c3c0d549b9853-ins_compl_add_infercase
 * @id cpp/vim/caea66442d86e7bbba3bf3dc202c3c0d549b9853/ins-compl-add-infercase
 * @description vim-caea66442d86e7bbba3bf3dc202c3c0d549b9853-src/insexpand.c-ins_compl_add_infercase CVE-2022-2343
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vactual_len_647, VariableAccess target_0) {
		target_0.getTarget()=vactual_len_647
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_1(Variable vactual_len_647, VariableAccess target_1) {
		target_1.getTarget()=vactual_len_647
}

predicate func_2(Parameter vlen_639, Variable vactual_len_647, VariableAccess target_2) {
		target_2.getTarget()=vactual_len_647
		and target_2.getParent().(AssignExpr).getLValue() = target_2
		and target_2.getParent().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlen_639
}

predicate func_3(Variable vactual_compl_length_648, VariableAccess target_3) {
		target_3.getTarget()=vactual_compl_length_648
		and target_3.getParent().(AssignExpr).getLValue() = target_3
		and target_3.getParent().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_4(Variable vactual_compl_length_648, VariableAccess target_4) {
		target_4.getTarget()=vactual_compl_length_648
}

predicate func_5(Variable vactual_compl_length_648, VariableAccess target_5) {
		target_5.getTarget()=vactual_compl_length_648
		and target_5.getParent().(AssignExpr).getLValue() = target_5
}

/*predicate func_6(Variable vactual_len_647, Variable vactual_compl_length_648, VariableAccess target_6) {
		target_6.getTarget()=vactual_len_647
		and target_6.getParent().(LTExpr).getGreaterOperand().(VariableAccess).getTarget()=vactual_compl_length_648
}

*/
/*predicate func_7(Variable vactual_len_647, Variable vactual_compl_length_648, VariableAccess target_7) {
		target_7.getTarget()=vactual_compl_length_648
		and target_7.getParent().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vactual_len_647
}

*/
predicate func_8(Variable vactual_len_647, VariableAccess target_8) {
		target_8.getTarget()=vactual_len_647
}

predicate func_9(Variable vactual_compl_length_648, VariableAccess target_9) {
		target_9.getTarget()=vactual_compl_length_648
}

/*predicate func_10(Variable vstr_645, Variable vactual_len_647, Variable vactual_compl_length_648, VariableAccess target_10) {
		target_10.getTarget()=vactual_len_647
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ins_compl_infercase_gettext")
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstr_645
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vactual_compl_length_648
}

*/
/*predicate func_11(Variable vstr_645, Variable vactual_len_647, Variable vactual_compl_length_648, VariableAccess target_11) {
		target_11.getTarget()=vactual_compl_length_648
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ins_compl_infercase_gettext")
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstr_645
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vactual_len_647
}

*/
predicate func_12(Variable vstr_645, Variable vactual_len_647, Variable vactual_compl_length_648) {
	exists(AddressOfExpr target_12 |
		target_12.getOperand().(VariableAccess).getType().hasName("char_u *")
		and target_12.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ins_compl_infercase_gettext")
		and target_12.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstr_645
		and target_12.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vactual_len_647
		and target_12.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vactual_compl_length_648)
}

predicate func_13(Function func) {
	exists(ExprStmt target_13 |
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_13.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_13 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_13))
}

predicate func_14(Function func) {
	exists(ExprStmt target_14 |
		target_14.getExpr().(FunctionCall).getTarget().hasName("vim_free")
		and target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char_u *")
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_14 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_14))
}

predicate func_16(Parameter vlen_639, Parameter vfname_641, Parameter vdir_642, Variable vstr_645, Variable vflags_650, FunctionCall target_16) {
		target_16.getTarget().hasName("ins_compl_add")
		and target_16.getArgument(0).(VariableAccess).getTarget()=vstr_645
		and target_16.getArgument(1).(VariableAccess).getTarget()=vlen_639
		and target_16.getArgument(2).(VariableAccess).getTarget()=vfname_641
		and target_16.getArgument(3).(Literal).getValue()="0"
		and target_16.getArgument(4).(Literal).getValue()="0"
		and target_16.getArgument(5).(VariableAccess).getTarget()=vdir_642
		and target_16.getArgument(6).(VariableAccess).getTarget()=vflags_650
		and target_16.getArgument(7).(Literal).getValue()="0"
}

from Function func, Parameter vlen_639, Parameter vfname_641, Parameter vdir_642, Variable vstr_645, Variable vactual_len_647, Variable vactual_compl_length_648, Variable vflags_650, VariableAccess target_0, VariableAccess target_1, VariableAccess target_2, VariableAccess target_3, VariableAccess target_4, VariableAccess target_5, VariableAccess target_8, VariableAccess target_9, FunctionCall target_16
where
func_0(vactual_len_647, target_0)
and func_1(vactual_len_647, target_1)
and func_2(vlen_639, vactual_len_647, target_2)
and func_3(vactual_compl_length_648, target_3)
and func_4(vactual_compl_length_648, target_4)
and func_5(vactual_compl_length_648, target_5)
and func_8(vactual_len_647, target_8)
and func_9(vactual_compl_length_648, target_9)
and not func_12(vstr_645, vactual_len_647, vactual_compl_length_648)
and not func_13(func)
and not func_14(func)
and func_16(vlen_639, vfname_641, vdir_642, vstr_645, vflags_650, target_16)
and vlen_639.getType().hasName("int")
and vfname_641.getType().hasName("char_u *")
and vdir_642.getType().hasName("int")
and vstr_645.getType().hasName("char_u *")
and vactual_len_647.getType().hasName("int")
and vactual_compl_length_648.getType().hasName("int")
and vflags_650.getType().hasName("int")
and vlen_639.getParentScope+() = func
and vfname_641.getParentScope+() = func
and vdir_642.getParentScope+() = func
and vstr_645.getParentScope+() = func
and vactual_len_647.getParentScope+() = func
and vactual_compl_length_648.getParentScope+() = func
and vflags_650.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
