/**
 * @name vim-caea66442d86e7bbba3bf3dc202c3c0d549b9853-ins_compl_infercase_gettext
 * @id cpp/vim/caea66442d86e7bbba3bf3dc202c3c0d549b9853/ins-compl-infercase-gettext
 * @description vim-caea66442d86e7bbba3bf3dc202c3c0d549b9853-src/insexpand.c-ins_compl_infercase_gettext CVE-2022-2343
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vactual_len_531, VariableAccess target_0) {
		target_0.getTarget()=vactual_len_531
}

predicate func_1(Parameter vactual_len_531, Variable vi_537, IfStmt target_14, VariableAccess target_1) {
		target_1.getTarget()=vactual_len_531
		and target_1.getParent().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vi_537
		and target_1.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_14
}

predicate func_2(Parameter vactual_compl_length_532, Variable vi_537, VariableAccess target_2) {
		target_2.getTarget()=vactual_compl_length_532
		and target_2.getParent().(AssignExpr).getRValue() = target_2
		and target_2.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_537
}

predicate func_3(Parameter vactual_len_531, Variable vi_537, ExprStmt target_15, VariableAccess target_3) {
		target_3.getTarget()=vactual_len_531
		and target_3.getParent().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vi_537
		and target_3.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_15
}

predicate func_4(Parameter vactual_compl_length_532, Variable vi_537, VariableAccess target_4) {
		target_4.getTarget()=vactual_compl_length_532
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_537
}

predicate func_5(Parameter vactual_len_531, Variable vi_537, ExprStmt target_16, VariableAccess target_5) {
		target_5.getTarget()=vactual_len_531
		and target_5.getParent().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vi_537
		and target_5.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_16
}

predicate func_6(Parameter vactual_len_531, VariableAccess target_6) {
		target_6.getTarget()=vactual_len_531
}

predicate func_7(Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("ga_init2")
		and target_7.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("garray_T")
		and target_7.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_7.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="500"
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_7))
}

predicate func_8(Variable vp_536, Variable vIObuff, Variable vhas_mbyte, LogicalAndExpr target_13, ReturnStmt target_17, IfStmt target_18, IfStmt target_12) {
	exists(IfStmt target_8 |
		target_8.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="ga_data"
		and target_8.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("garray_T")
		and target_8.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("ga_grow")
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("garray_T")
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(Literal).getValue()="10"
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ga_clear")
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(StringLiteral).getValue()="[failed]"
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_536
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="ga_data"
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("garray_T")
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="ga_len"
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("garray_T")
		and target_8.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(VariableAccess).getTarget()=vhas_mbyte
		and target_8.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ga_len"
		and target_8.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("garray_T")
		and target_8.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(ExprCall).getArgument(1).(VariableAccess).getTarget()=vp_536
		and target_8.getThen().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PrefixIncrExpr).getOperand().(ValueFieldAccess).getTarget().getName()="ga_len"
		and target_8.getElse().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_8.getElse().(IfStmt).getCondition().(RelationalOperation).getLesserOperand() instanceof AddExpr
		and target_8.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("ga_grow")
		and target_8.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(StringLiteral).getValue()="[failed]"
		and target_8.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("strcpy")
		and target_8.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="ga_data"
		and target_8.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("garray_T")
		and target_8.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vIObuff
		and target_8.getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ga_len"
		and target_8.getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("garray_T")
		and target_8.getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strlen")
		and target_8.getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vIObuff
		and target_8.getElse().(IfStmt).getElse() instanceof IfStmt
		and target_8.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_17.getExpr().(VariableAccess).getLocation())
		and target_18.getCondition().(VariableAccess).getLocation().isBefore(target_8.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(VariableAccess).getLocation())
		and target_8.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(VariableAccess).getLocation().isBefore(target_12.getCondition().(VariableAccess).getLocation()))
}

predicate func_9(Function func) {
	exists(IfStmt target_9 |
		target_9.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="ga_data"
		and target_9.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("garray_T")
		and target_9.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("char_u **")
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="ga_data"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("garray_T")
		and target_9.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(ValueFieldAccess).getTarget().getName()="ga_data"
		and target_9.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("garray_T")
		and (func.getEntryPoint().(BlockStmt).getStmt(21)=target_9 or func.getEntryPoint().(BlockStmt).getStmt(21).getFollowingStmt()=target_9))
}

predicate func_10(Variable vp_536, Variable vIObuff, AddExpr target_10) {
		target_10.getAnOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vp_536
		and target_10.getAnOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vIObuff
		and target_10.getAnOperand().(Literal).getValue()="6"
}

predicate func_11(Function func, AddExpr target_11) {
		target_11.getValue()="1025"
		and target_11.getEnclosingFunction() = func
}

predicate func_12(Variable vwca_535, Variable vp_536, Variable vi_537, Variable vhas_mbyte, Variable vmb_char2bytes, LogicalAndExpr target_13, IfStmt target_12) {
		target_12.getCondition().(VariableAccess).getTarget()=vhas_mbyte
		and target_12.getThen().(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vp_536
		and target_12.getThen().(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vmb_char2bytes
		and target_12.getThen().(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(ExprCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwca_535
		and target_12.getThen().(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(ExprCall).getArgument(0).(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_537
		and target_12.getThen().(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(ExprCall).getArgument(1).(VariableAccess).getTarget()=vp_536
		and target_12.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vp_536
		and target_12.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwca_535
		and target_12.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_537
		and target_12.getParent().(WhileStmt).getCondition()=target_13
}

predicate func_13(Parameter vactual_len_531, Variable vi_537, LogicalAndExpr target_13) {
		target_13.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_537
		and target_13.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vactual_len_531
		and target_13.getAnOperand().(RelationalOperation).getLesserOperand() instanceof AddExpr
		and target_13.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
}

predicate func_14(Variable vwca_535, Variable vp_536, Variable vi_537, Variable vhas_mbyte, IfStmt target_14) {
		target_14.getCondition().(VariableAccess).getTarget()=vhas_mbyte
		and target_14.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwca_535
		and target_14.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_537
		and target_14.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("mb_ptr2char_adv")
		and target_14.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp_536
		and target_14.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwca_535
		and target_14.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_537
		and target_14.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vp_536
}

predicate func_15(Variable vwca_535, Variable vi_537, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwca_535
		and target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_537
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("vim_tolower")
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwca_535
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_537
}

predicate func_16(Variable vwca_535, Variable vi_537, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwca_535
		and target_16.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_537
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("vim_toupper")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vwca_535
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_537
}

predicate func_17(Variable vIObuff, ReturnStmt target_17) {
		target_17.getExpr().(VariableAccess).getTarget()=vIObuff
}

predicate func_18(Variable vp_536, Variable vhas_mbyte, IfStmt target_18) {
		target_18.getCondition().(VariableAccess).getTarget()=vhas_mbyte
		and target_18.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("mb_ptr2char_adv")
		and target_18.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp_536
		and target_18.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vp_536
}

from Function func, Parameter vactual_len_531, Parameter vactual_compl_length_532, Variable vwca_535, Variable vp_536, Variable vi_537, Variable vIObuff, Variable vhas_mbyte, Variable vmb_char2bytes, VariableAccess target_0, VariableAccess target_1, VariableAccess target_2, VariableAccess target_3, VariableAccess target_4, VariableAccess target_5, VariableAccess target_6, AddExpr target_10, AddExpr target_11, IfStmt target_12, LogicalAndExpr target_13, IfStmt target_14, ExprStmt target_15, ExprStmt target_16, ReturnStmt target_17, IfStmt target_18
where
func_0(vactual_len_531, target_0)
and func_1(vactual_len_531, vi_537, target_14, target_1)
and func_2(vactual_compl_length_532, vi_537, target_2)
and func_3(vactual_len_531, vi_537, target_15, target_3)
and func_4(vactual_compl_length_532, vi_537, target_4)
and func_5(vactual_len_531, vi_537, target_16, target_5)
and func_6(vactual_len_531, target_6)
and not func_7(func)
and not func_8(vp_536, vIObuff, vhas_mbyte, target_13, target_17, target_18, target_12)
and not func_9(func)
and func_10(vp_536, vIObuff, target_10)
and func_11(func, target_11)
and func_12(vwca_535, vp_536, vi_537, vhas_mbyte, vmb_char2bytes, target_13, target_12)
and func_13(vactual_len_531, vi_537, target_13)
and func_14(vwca_535, vp_536, vi_537, vhas_mbyte, target_14)
and func_15(vwca_535, vi_537, target_15)
and func_16(vwca_535, vi_537, target_16)
and func_17(vIObuff, target_17)
and func_18(vp_536, vhas_mbyte, target_18)
and vactual_len_531.getType().hasName("int")
and vactual_compl_length_532.getType().hasName("int")
and vwca_535.getType().hasName("int *")
and vp_536.getType().hasName("char_u *")
and vi_537.getType().hasName("int")
and vIObuff.getType().hasName("char_u *")
and vhas_mbyte.getType().hasName("int")
and vmb_char2bytes.getType().hasName("..(*)(..)")
and vactual_len_531.getParentScope+() = func
and vactual_compl_length_532.getParentScope+() = func
and vwca_535.getParentScope+() = func
and vp_536.getParentScope+() = func
and vi_537.getParentScope+() = func
and not vIObuff.getParentScope+() = func
and not vhas_mbyte.getParentScope+() = func
and not vmb_char2bytes.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
