/**
 * @name vim-9f1a39a5d1cd7989ada2d1cb32f97d84360e050f-get_function_line
 * @id cpp/vim/9f1a39a5d1cd7989ada2d1cb32f97d84360e050f/get-function-line
 * @description vim-9f1a39a5d1cd7989ada2d1cb32f97d84360e050f-src/userfunc.c-get_function_line CVE-2022-0156
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter veap_174, ExprStmt target_7, ExprStmt target_8) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="ga_len"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("garray_T *")
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cmdlinep"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_174
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ga_data"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("garray_T *")
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="ga_len"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("garray_T *")
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getParent().(IfStmt).getThen()=target_7
		and target_8.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_1(Parameter veap_174, ExprStmt target_7) {
	exists(ArrayExpr target_1 |
		target_1.getArrayBase().(PointerFieldAccess).getTarget().getName()="ga_data"
		and target_1.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("garray_T *")
		and target_1.getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="ga_len"
		and target_1.getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("garray_T *")
		and target_1.getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_1.getParent().(EQExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cmdlinep"
		and target_1.getParent().(EQExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_174
		and target_1.getParent().(EQExpr).getAnOperand() instanceof PointerDereferenceExpr
		and target_1.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_7)
}

*/
predicate func_2(Variable vtheline_179, ExprStmt target_7, ReturnStmt target_9) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("ga_add_string")
		and target_2.getArgument(0).(VariableAccess).getType().hasName("garray_T *")
		and target_2.getArgument(1).(VariableAccess).getTarget()=vtheline_179
		and target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_2.getArgument(1).(VariableAccess).getLocation())
		and target_2.getArgument(1).(VariableAccess).getLocation().isBefore(target_9.getExpr().(VariableAccess).getLocation()))
}

predicate func_3(Variable vtheline_179, VariableAccess target_3) {
		target_3.getTarget()=vtheline_179
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue() instanceof PointerDereferenceExpr
}

predicate func_4(Parameter veap_174, Parameter vline_to_free_175, ExprStmt target_7, ExprStmt target_8, PointerDereferenceExpr target_10, PointerDereferenceExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vline_to_free_175
		and target_4.getParent().(EQExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cmdlinep"
		and target_4.getParent().(EQExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_174
		and target_4.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_7
		and target_8.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getParent().(EQExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_10.getOperand().(VariableAccess).getLocation())
}

predicate func_5(Parameter vline_to_free_175, FunctionCall target_5) {
		target_5.getTarget().hasName("vim_free")
		and target_5.getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vline_to_free_175
}

predicate func_6(Parameter vline_to_free_175, Variable vtheline_179, EqualityOperation target_11, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vline_to_free_175
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vtheline_179
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_7(Parameter veap_174, Variable vtheline_179, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cmdlinep"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_174
		and target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vtheline_179
}

predicate func_8(Parameter veap_174, Variable vtheline_179, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtheline_179
		and target_8.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="getline"
		and target_8.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_174
		and target_8.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(CharLiteral).getValue()="58"
		and target_8.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="cookie"
		and target_8.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_174
}

predicate func_9(Variable vtheline_179, ReturnStmt target_9) {
		target_9.getExpr().(VariableAccess).getTarget()=vtheline_179
}

predicate func_10(Parameter vline_to_free_175, PointerDereferenceExpr target_10) {
		target_10.getOperand().(VariableAccess).getTarget()=vline_to_free_175
}

predicate func_11(Variable vtheline_179, EqualityOperation target_11) {
		target_11.getAnOperand().(VariableAccess).getTarget()=vtheline_179
		and target_11.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter veap_174, Parameter vline_to_free_175, Variable vtheline_179, VariableAccess target_3, PointerDereferenceExpr target_4, FunctionCall target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, ReturnStmt target_9, PointerDereferenceExpr target_10, EqualityOperation target_11
where
not func_0(veap_174, target_7, target_8)
and not func_2(vtheline_179, target_7, target_9)
and func_3(vtheline_179, target_3)
and func_4(veap_174, vline_to_free_175, target_7, target_8, target_10, target_4)
and func_5(vline_to_free_175, target_5)
and func_6(vline_to_free_175, vtheline_179, target_11, target_6)
and func_7(veap_174, vtheline_179, target_7)
and func_8(veap_174, vtheline_179, target_8)
and func_9(vtheline_179, target_9)
and func_10(vline_to_free_175, target_10)
and func_11(vtheline_179, target_11)
and veap_174.getType().hasName("exarg_T *")
and vline_to_free_175.getType().hasName("char_u **")
and vtheline_179.getType().hasName("char_u *")
and veap_174.getParentScope+() = func
and vline_to_free_175.getParentScope+() = func
and vtheline_179.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
