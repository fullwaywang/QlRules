/**
 * @name libass-6835731c2fe4164a0c50bc91d12c43b2a2b4e799-parse_tags
 * @id cpp/libass/6835731c2fe4164a0c50bc91d12c43b2a2b4e799/parse-tags
 * @description libass-6835731c2fe4164a0c50bc91d12c43b2a2b4e799-libass/ass_parse.c-parse_tags CVE-2020-24994
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vp_233, Parameter vend_233, Parameter vpwr_233, Variable vq_235, Variable vargs_253, Variable vcnt_618, Variable vk_620, FunctionCall target_2, ExprStmt target_3, EqualityOperation target_4, ExprStmt target_5, ExprStmt target_6, ArrayExpr target_7, ArrayExpr target_8, ExprStmt target_9, ExprStmt target_1) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="end"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vargs_253
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcnt_618
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vend_233
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(SizeofExprOperator).getValue()="4"
		and target_0.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpwr_233
		and target_0.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vk_620
		and target_0.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vq_235
		and target_0.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vp_233
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(11)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_4.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_0.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_0.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_7.getArrayBase().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_8.getArrayBase().(VariableAccess).getLocation())
		and target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_0.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vp_233, Variable vargs_253, Parameter vrender_priv_233, Variable vcnt_618, Variable vk_620, FunctionCall target_2, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_233
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("parse_tags")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrender_priv_233
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_233
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="end"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vargs_253
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcnt_618
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vk_620
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Parameter vp_233, FunctionCall target_2) {
		target_2.getTarget().hasName("mystrcmp")
		and target_2.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp_233
		and target_2.getArgument(1).(StringLiteral).getValue()="t"
}

predicate func_3(Parameter vp_233, Variable vargs_253, Variable vcnt_618, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_233
		and target_3.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="start"
		and target_3.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vargs_253
		and target_3.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcnt_618
}

predicate func_4(Parameter vend_233, Variable vq_235, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vq_235
		and target_4.getAnOperand().(VariableAccess).getTarget()=vend_233
}

predicate func_5(Parameter vpwr_233, Parameter vrender_priv_233, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("change_alpha")
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="c"
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrender_priv_233
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vpwr_233
}

predicate func_6(Parameter vpwr_233, Parameter vrender_priv_233, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="clip_x0"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrender_priv_233
		and target_6.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="clip_x0"
		and target_6.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_6.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrender_priv_233
		and target_6.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SubExpr).getLeftOperand().(Literal).getValue()="1"
		and target_6.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vpwr_233
		and target_6.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vpwr_233
}

predicate func_7(Variable vargs_253, Variable vcnt_618, ArrayExpr target_7) {
		target_7.getArrayBase().(VariableAccess).getTarget()=vargs_253
		and target_7.getArrayOffset().(VariableAccess).getTarget()=vcnt_618
}

predicate func_8(Variable vargs_253, Variable vcnt_618, ArrayExpr target_8) {
		target_8.getArrayBase().(VariableAccess).getTarget()=vargs_253
		and target_8.getArrayOffset().(VariableAccess).getTarget()=vcnt_618
}

predicate func_9(Variable vk_620, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vk_620
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pow")
}

from Function func, Parameter vp_233, Parameter vend_233, Parameter vpwr_233, Variable vq_235, Variable vargs_253, Parameter vrender_priv_233, Variable vcnt_618, Variable vk_620, ExprStmt target_1, FunctionCall target_2, ExprStmt target_3, EqualityOperation target_4, ExprStmt target_5, ExprStmt target_6, ArrayExpr target_7, ArrayExpr target_8, ExprStmt target_9
where
not func_0(vp_233, vend_233, vpwr_233, vq_235, vargs_253, vcnt_618, vk_620, target_2, target_3, target_4, target_5, target_6, target_7, target_8, target_9, target_1)
and func_1(vp_233, vargs_253, vrender_priv_233, vcnt_618, vk_620, target_2, target_1)
and func_2(vp_233, target_2)
and func_3(vp_233, vargs_253, vcnt_618, target_3)
and func_4(vend_233, vq_235, target_4)
and func_5(vpwr_233, vrender_priv_233, target_5)
and func_6(vpwr_233, vrender_priv_233, target_6)
and func_7(vargs_253, vcnt_618, target_7)
and func_8(vargs_253, vcnt_618, target_8)
and func_9(vk_620, target_9)
and vp_233.getType().hasName("char *")
and vend_233.getType().hasName("char *")
and vpwr_233.getType().hasName("double")
and vq_235.getType().hasName("char *")
and vargs_253.getType().hasName("arg[8]")
and vrender_priv_233.getType().hasName("ASS_Renderer *")
and vcnt_618.getType().hasName("int")
and vk_620.getType().hasName("double")
and vp_233.getParentScope+() = func
and vend_233.getParentScope+() = func
and vpwr_233.getParentScope+() = func
and vq_235.getParentScope+() = func
and vargs_253.getParentScope+() = func
and vrender_priv_233.getParentScope+() = func
and vcnt_618.getParentScope+() = func
and vk_620.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
