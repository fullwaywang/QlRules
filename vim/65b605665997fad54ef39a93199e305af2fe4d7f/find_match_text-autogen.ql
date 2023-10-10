/**
 * @name vim-65b605665997fad54ef39a93199e305af2fe4d7f-find_match_text
 * @id cpp/vim/65b605665997fad54ef39a93199e305af2fe4d7f/find-match-text
 * @description vim-65b605665997fad54ef39a93199e305af2fe4d7f-src/regexp_nfa.c-find_match_text CVE-2021-3778
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable venc_utf8, Variable vcol_5649, Variable vlen2_5651, Variable vrex, LogicalAndExpr target_2, LogicalAndExpr target_3, ExprStmt target_4, PointerArithmeticOperation target_5, ExprStmt target_6) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(VariableAccess).getTarget()=venc_utf8
		and target_0.getThen().(FunctionCall).getTarget().hasName("utf_ptr2len")
		and target_0.getThen().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="line"
		and target_0.getThen().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrex
		and target_0.getThen().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vcol_5649
		and target_0.getThen().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlen2_5651
		and target_0.getElse() instanceof ConditionalExpr
		and target_0.getParent().(AssignAddExpr).getRValue() = target_0
		and target_0.getParent().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlen2_5651
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ConditionalExpr).getCondition().(VariableAccess).getLocation().isBefore(target_0.getCondition().(VariableAccess).getLocation())
		and target_0.getCondition().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getThen().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getThen().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getThen().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vc2_5650, Variable vlen2_5651, Variable vhas_mbyte, Variable vmb_char2len, ConditionalExpr target_1) {
		target_1.getCondition().(VariableAccess).getTarget()=vhas_mbyte
		and target_1.getThen().(VariableCall).getExpr().(VariableAccess).getTarget()=vmb_char2len
		and target_1.getThen().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vc2_5650
		and target_1.getElse().(Literal).getValue()="1"
		and target_1.getParent().(AssignAddExpr).getRValue() = target_1
		and target_1.getParent().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlen2_5651
}

predicate func_2(Variable venc_utf8, Variable vc2_5650, Variable vrex, LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vc2_5650
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="reg_ic"
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrex
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ConditionalExpr).getCondition().(VariableAccess).getTarget()=venc_utf8
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("utf_fold")
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("vim_tolower")
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ConditionalExpr).getCondition().(VariableAccess).getTarget()=venc_utf8
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("utf_fold")
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc2_5650
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("vim_tolower")
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc2_5650
}

predicate func_3(Variable venc_utf8, Variable vhas_mbyte, LogicalAndExpr target_3) {
		target_3.getAnOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=venc_utf8
		and target_3.getAnOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("utf_iscomposing")
		and target_3.getAnOperand().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vhas_mbyte
}

predicate func_4(Variable vcol_5649, Variable vc2_5650, Variable vlen2_5651, Variable vhas_mbyte, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc2_5650
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vhas_mbyte
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="line"
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vcol_5649
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlen2_5651
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="line"
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vcol_5649
		and target_4.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlen2_5651
}

predicate func_5(Variable vcol_5649, Variable vlen2_5651, Variable vrex, PointerArithmeticOperation target_5) {
		target_5.getAnOperand().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="line"
		and target_5.getAnOperand().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrex
		and target_5.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vcol_5649
		and target_5.getAnOperand().(VariableAccess).getTarget()=vlen2_5651
}

predicate func_6(Variable vlen2_5651, ExprStmt target_6) {
		target_6.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlen2_5651
		and target_6.getExpr().(AssignAddExpr).getRValue() instanceof ConditionalExpr
}

from Function func, Variable venc_utf8, Variable vcol_5649, Variable vc2_5650, Variable vlen2_5651, Variable vhas_mbyte, Variable vmb_char2len, Variable vrex, ConditionalExpr target_1, LogicalAndExpr target_2, LogicalAndExpr target_3, ExprStmt target_4, PointerArithmeticOperation target_5, ExprStmt target_6
where
not func_0(venc_utf8, vcol_5649, vlen2_5651, vrex, target_2, target_3, target_4, target_5, target_6)
and func_1(vc2_5650, vlen2_5651, vhas_mbyte, vmb_char2len, target_1)
and func_2(venc_utf8, vc2_5650, vrex, target_2)
and func_3(venc_utf8, vhas_mbyte, target_3)
and func_4(vcol_5649, vc2_5650, vlen2_5651, vhas_mbyte, target_4)
and func_5(vcol_5649, vlen2_5651, vrex, target_5)
and func_6(vlen2_5651, target_6)
and venc_utf8.getType().hasName("int")
and vcol_5649.getType().hasName("colnr_T")
and vc2_5650.getType().hasName("int")
and vlen2_5651.getType().hasName("int")
and vhas_mbyte.getType().hasName("int")
and vmb_char2len.getType().hasName("..(*)(..)")
and vrex.getType().hasName("regexec_T")
and not venc_utf8.getParentScope+() = func
and vcol_5649.getParentScope+() = func
and vc2_5650.getParentScope+() = func
and vlen2_5651.getParentScope+() = func
and not vhas_mbyte.getParentScope+() = func
and not vmb_char2len.getParentScope+() = func
and not vrex.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
