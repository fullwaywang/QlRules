/**
 * @name vim-9f1a39a5d1cd7989ada2d1cb32f97d84360e050f-lambda_function_body
 * @id cpp/vim/9f1a39a5d1cd7989ada2d1cb32f97d84360e050f/lambda-function-body
 * @description vim-9f1a39a5d1cd7989ada2d1cb32f97d84360e050f-src/userfunc.c-lambda_function_body CVE-2022-0156
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vevalarg_1106, Variable veap_1117, ExprStmt target_14, ExprStmt target_15) {
	exists(AddressOfExpr target_0 |
		target_0.getOperand().(PointerFieldAccess).getTarget().getName()="eval_tofree_ga"
		and target_0.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vevalarg_1106
		and target_0.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("get_function_body")
		and target_0.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=veap_1117
		and target_0.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_0.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3) instanceof AddressOfExpr
		and target_14.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(EqualityOperation target_16, Function func, DeclStmt target_1) {
		target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable veap_1117, Parameter varg_1104, EqualityOperation target_16, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=varg_1104
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="nextcmd"
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_1117
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
}

predicate func_3(Variable vtfgap_1201, BlockStmt target_17, EqualityOperation target_3) {
		target_3.getAnOperand().(FunctionCall).getTarget().hasName("ga_grow")
		and target_3.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtfgap_1201
		and target_3.getAnOperand().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_3.getAnOperand().(Literal).getValue()="1"
		and target_3.getParent().(IfStmt).getThen()=target_17
}

predicate func_4(Variable vcmdline_1119, Variable vtfgap_1201, EqualityOperation target_3, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ga_data"
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtfgap_1201
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ga_len"
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtfgap_1201
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcmdline_1119
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_5(Parameter vevalarg_1106, EqualityOperation target_3, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="eval_using_cmdline"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vevalarg_1106
		and target_5.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_6(EqualityOperation target_18, Function func, GotoStmt target_6) {
		target_6.toString() = "goto ..."
		and target_6.getName() ="erret"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Function func, DeclStmt target_7) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_8(Variable veap_1117, Variable vline_to_free_1121, AddressOfExpr target_8) {
		target_8.getOperand().(VariableAccess).getTarget()=vline_to_free_1121
		and target_8.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("get_function_body")
		and target_8.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=veap_1117
		and target_8.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_9(Variable vcmdline_1119, Variable vline_to_free_1121, ExprStmt target_10, EqualityOperation target_9) {
		target_9.getAnOperand().(VariableAccess).getTarget()=vcmdline_1119
		and target_9.getAnOperand().(VariableAccess).getTarget()=vline_to_free_1121
		and target_9.getParent().(IfStmt).getThen()=target_10
}

predicate func_10(Variable vcmdline_1119, EqualityOperation target_9, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("vim_free")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcmdline_1119
		and target_10.getParent().(IfStmt).getCondition()=target_9
}

predicate func_11(Variable vcmdline_1119, Variable vline_to_free_1121, EqualityOperation target_16, IfStmt target_11) {
		target_11.getCondition() instanceof EqualityOperation
		and target_11.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_11.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_11.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcmdline_1119
		and target_11.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vline_to_free_1121
		and target_11.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vline_to_free_1121
		and target_11.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
}

/*predicate func_12(Variable vcmdline_1119, Variable vline_to_free_1121, EqualityOperation target_3, IfStmt target_12) {
		target_12.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcmdline_1119
		and target_12.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vline_to_free_1121
		and target_12.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vline_to_free_1121
		and target_12.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

*/
predicate func_13(Variable vline_to_free_1121, Function func, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("vim_free")
		and target_13.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_to_free_1121
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_13
}

predicate func_14(Parameter vevalarg_1106, Variable veap_1117, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="cookie"
		and target_14.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_1117
		and target_14.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="eval_cookie"
		and target_14.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vevalarg_1106
}

predicate func_15(Parameter vevalarg_1106, ExprStmt target_15) {
		target_15.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="eval_break_count"
		and target_15.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vevalarg_1106
		and target_15.getExpr().(AssignAddExpr).getRValue().(ValueFieldAccess).getTarget().getName()="ga_len"
}

predicate func_16(Variable veap_1117, EqualityOperation target_16) {
		target_16.getAnOperand().(ValueFieldAccess).getTarget().getName()="nextcmd"
		and target_16.getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_1117
		and target_16.getAnOperand().(Literal).getValue()="0"
}

predicate func_17(BlockStmt target_17) {
		target_17.getStmt(0) instanceof ExprStmt
		and target_17.getStmt(1) instanceof ExprStmt
		and target_17.getStmt(2) instanceof IfStmt
}

predicate func_18(Variable veap_1117, EqualityOperation target_18) {
		target_18.getAnOperand().(FunctionCall).getTarget().hasName("get_function_body")
		and target_18.getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=veap_1117
		and target_18.getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_18.getAnOperand().(FunctionCall).getArgument(3) instanceof AddressOfExpr
		and target_18.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vevalarg_1106, Variable veap_1117, Parameter varg_1104, Variable vcmdline_1119, Variable vline_to_free_1121, Variable vtfgap_1201, DeclStmt target_1, ExprStmt target_2, EqualityOperation target_3, ExprStmt target_4, ExprStmt target_5, GotoStmt target_6, DeclStmt target_7, AddressOfExpr target_8, EqualityOperation target_9, ExprStmt target_10, IfStmt target_11, ExprStmt target_13, ExprStmt target_14, ExprStmt target_15, EqualityOperation target_16, BlockStmt target_17, EqualityOperation target_18
where
not func_0(vevalarg_1106, veap_1117, target_14, target_15)
and func_1(target_16, func, target_1)
and func_2(veap_1117, varg_1104, target_16, target_2)
and func_3(vtfgap_1201, target_17, target_3)
and func_4(vcmdline_1119, vtfgap_1201, target_3, target_4)
and func_5(vevalarg_1106, target_3, target_5)
and func_6(target_18, func, target_6)
and func_7(func, target_7)
and func_8(veap_1117, vline_to_free_1121, target_8)
and func_9(vcmdline_1119, vline_to_free_1121, target_10, target_9)
and func_10(vcmdline_1119, target_9, target_10)
and func_11(vcmdline_1119, vline_to_free_1121, target_16, target_11)
and func_13(vline_to_free_1121, func, target_13)
and func_14(vevalarg_1106, veap_1117, target_14)
and func_15(vevalarg_1106, target_15)
and func_16(veap_1117, target_16)
and func_17(target_17)
and func_18(veap_1117, target_18)
and vevalarg_1106.getType().hasName("evalarg_T *")
and veap_1117.getType().hasName("exarg_T")
and varg_1104.getType().hasName("char_u **")
and vcmdline_1119.getType().hasName("char_u *")
and vline_to_free_1121.getType().hasName("char_u *")
and vtfgap_1201.getType().hasName("garray_T *")
and vevalarg_1106.getParentScope+() = func
and veap_1117.getParentScope+() = func
and varg_1104.getParentScope+() = func
and vcmdline_1119.getParentScope+() = func
and vline_to_free_1121.getParentScope+() = func
and vtfgap_1201.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
