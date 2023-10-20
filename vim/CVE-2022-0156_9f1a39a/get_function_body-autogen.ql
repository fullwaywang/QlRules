/**
 * @name vim-9f1a39a5d1cd7989ada2d1cb32f97d84360e050f-get_function_body
 * @id cpp/vim/9f1a39a5d1cd7989ada2d1cb32f97d84360e050f/get-function-body
 * @description vim-9f1a39a5d1cd7989ada2d1cb32f97d84360e050f-src/userfunc.c-get_function_body CVE-2022-0156
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="1"
		and target_0.getParent().(AssignExpr).getParent().(ExprStmt).getExpr() instanceof AssignExpr
		and target_0.getEnclosingFunction() = func
}

predicate func_2(BlockStmt target_13, Function func) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="ga_len"
		and target_2.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("garray_T *")
		and target_2.getLesserOperand() instanceof Literal
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof PointerDereferenceExpr
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_2.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_13
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(ArrayExpr target_3 |
		target_3.getArrayBase().(PointerFieldAccess).getTarget().getName()="ga_data"
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("garray_T *")
		and target_3.getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="ga_len"
		and target_3.getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("garray_T *")
		and target_3.getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Parameter veap_677) {
	exists(ArrayExpr target_4 |
		target_4.getArrayBase().(PointerFieldAccess).getTarget().getName()="ga_data"
		and target_4.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("garray_T *")
		and target_4.getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="ga_len"
		and target_4.getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("garray_T *")
		and target_4.getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cmdlinep"
		and target_4.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_677)
}

predicate func_5(Function func) {
	exists(PrefixDecrExpr target_5 |
		target_5.getOperand().(PointerFieldAccess).getTarget().getName()="ga_len"
		and target_5.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("garray_T *")
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Parameter veap_677, PointerDereferenceExpr target_6) {
		target_6.getOperand().(PointerFieldAccess).getTarget().getName()="cmdlinep"
		and target_6.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_677
}

predicate func_8(Parameter vline_to_free_680, Parameter veap_677, ExprStmt target_15, EqualityOperation target_16, VariableAccess target_8) {
		target_8.getTarget()=vline_to_free_680
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_function_line")
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=veap_677
		and target_15.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_16.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_9(Parameter vline_to_free_680, ExprStmt target_17, PointerDereferenceExpr target_9) {
		target_9.getOperand().(VariableAccess).getTarget()=vline_to_free_680
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_9.getOperand().(VariableAccess).getLocation())
}

predicate func_10(Parameter vline_to_free_680, BlockStmt target_13, EqualityOperation target_10) {
		target_10.getAnOperand() instanceof PointerDereferenceExpr
		and target_10.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vline_to_free_680
		and target_10.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_13
}

predicate func_11(Parameter vline_to_free_680, Parameter veap_677, PointerDereferenceExpr target_21, LogicalAndExpr target_22, PointerDereferenceExpr target_11) {
		target_11.getOperand().(VariableAccess).getTarget()=vline_to_free_680
		and target_11.getParent().(AssignExpr).getRValue() = target_11
		and target_11.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cmdlinep"
		and target_11.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_677
		and target_21.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_11.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_22.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_12(Parameter vline_to_free_680, AssignExpr target_12) {
		target_12.getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vline_to_free_680
		and target_12.getRValue() instanceof Literal
}

predicate func_13(Parameter veap_677, BlockStmt target_13) {
		target_13.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vim_free")
		and target_13.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cmdlinep"
		and target_13.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_677
		and target_13.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cmdlinep"
		and target_13.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_677
		and target_13.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof PointerDereferenceExpr
}

predicate func_15(Parameter veap_677, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_15.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="cmdidx"
		and target_15.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_677
}

predicate func_16(Parameter veap_677, EqualityOperation target_16) {
		target_16.getAnOperand().(PointerFieldAccess).getTarget().getName()="cmdidx"
		and target_16.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_677
}

predicate func_17(Parameter vline_to_free_680, Parameter veap_677, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_function_line")
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=veap_677
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vline_to_free_680
}

predicate func_21(Parameter veap_677, PointerDereferenceExpr target_21) {
		target_21.getOperand().(PointerFieldAccess).getTarget().getName()="cmdlinep"
		and target_21.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_677
}

predicate func_22(Parameter veap_677, LogicalAndExpr target_22) {
		target_22.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="cmdidx"
		and target_22.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_677
		and target_22.getAnOperand().(FunctionCall).getTarget().hasName("checkforcmd")
		and target_22.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="enddef"
		and target_22.getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="4"
}

from Function func, Parameter vline_to_free_680, Parameter veap_677, Literal target_0, PointerDereferenceExpr target_6, VariableAccess target_8, PointerDereferenceExpr target_9, EqualityOperation target_10, PointerDereferenceExpr target_11, AssignExpr target_12, BlockStmt target_13, ExprStmt target_15, EqualityOperation target_16, ExprStmt target_17, PointerDereferenceExpr target_21, LogicalAndExpr target_22
where
func_0(func, target_0)
and not func_2(target_13, func)
and not func_3(func)
and not func_4(veap_677)
and not func_5(func)
and func_6(veap_677, target_6)
and func_8(vline_to_free_680, veap_677, target_15, target_16, target_8)
and func_9(vline_to_free_680, target_17, target_9)
and func_10(vline_to_free_680, target_13, target_10)
and func_11(vline_to_free_680, veap_677, target_21, target_22, target_11)
and func_12(vline_to_free_680, target_12)
and func_13(veap_677, target_13)
and func_15(veap_677, target_15)
and func_16(veap_677, target_16)
and func_17(vline_to_free_680, veap_677, target_17)
and func_21(veap_677, target_21)
and func_22(veap_677, target_22)
and vline_to_free_680.getType().hasName("char_u **")
and veap_677.getType().hasName("exarg_T *")
and vline_to_free_680.getParentScope+() = func
and veap_677.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
