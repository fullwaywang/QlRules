/**
 * @name vim-79481367a457951aabd9501b510fd7e3eb29c3d8-eval0_retarg
 * @id cpp/vim/79481367a457951aabd9501b510fd7e3eb29c3d8/eval0-retarg
 * @description vim-79481367a457951aabd9501b510fd7e3eb29c3d8-src/eval.c-eval0_retarg CVE-2022-2231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter veap_2375, Variable vp_2380, LogicalAndExpr target_13, LogicalAndExpr target_14, ExprStmt target_15) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vp_2380
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(FunctionCall).getTarget().hasName("skipwhite")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_2380
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="124"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nextcmd"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_2375
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("check_nextcmd")
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_2380
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

/*predicate func_1(Variable vp_2380, ExprStmt target_16, LogicalAndExpr target_13) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vp_2380
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(FunctionCall).getTarget().hasName("skipwhite")
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_2380
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="124"
		and target_1.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_16
		and target_13.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation()))
}

*/
predicate func_2(Variable vp_2380, Variable vexpr_end_2381, Function func, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vexpr_end_2381
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vp_2380
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Variable vp_2380, Function func, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_2380
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("skipwhite")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_2380
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Variable vret_2379, Variable vend_error_2386, BlockStmt target_17, LogicalOrExpr target_4) {
		target_4.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_2379
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(VariableAccess).getTarget()=vend_error_2386
		and target_4.getParent().(IfStmt).getThen()=target_17
}

predicate func_5(Parameter vrettv_2374, Variable vret_2379, LogicalOrExpr target_4, IfStmt target_5) {
		target_5.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_2379
		and target_5.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("clear_tv")
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrettv_2374
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_6(Parameter varg_2373, Variable vp_2380, Variable vdid_emsg_before_2382, Variable vdid_emsg, Variable vcalled_emsg_before_2383, Variable vcalled_emsg, Variable vflags_2384, Variable vend_error_2386, Variable ve_trailing_characters_str, Variable ve_invalid_expression_str, LogicalOrExpr target_4, IfStmt target_6) {
		target_6.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("aborting")
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdid_emsg
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdid_emsg_before_2382
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcalled_emsg
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcalled_emsg_before_2383
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_2384
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2"
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("in_vim9script")
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("vim9_bad_comment")
		and target_6.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_2380
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(VariableAccess).getTarget()=vend_error_2386
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("semsg")
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("dcgettext")
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(VariableAccess).getTarget()=ve_trailing_characters_str
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2).(Literal).getValue()="5"
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_2380
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("semsg")
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("dcgettext")
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(VariableAccess).getTarget()=ve_invalid_expression_str
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2).(Literal).getValue()="5"
		and target_6.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=varg_2373
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

/*predicate func_7(Parameter veap_2375, EqualityOperation target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=veap_2375
		and target_7.getAnOperand().(Literal).getValue()="0"
}

*/
predicate func_8(Parameter veap_2375, Variable vp_2380, ExprStmt target_16, EqualityOperation target_8) {
		target_8.getAnOperand().(ArrayExpr).getArrayBase().(FunctionCall).getTarget().hasName("skipwhite")
		and target_8.getAnOperand().(ArrayExpr).getArrayBase().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_2380
		and target_8.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_8.getAnOperand().(CharLiteral).getValue()="124"
		and target_8.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=veap_2375
		and target_8.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(FunctionCall).getTarget().hasName("skipwhite")
		and target_8.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_2380
		and target_8.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_8.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="124"
		and target_8.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_16
}

predicate func_9(LogicalOrExpr target_4, Function func, ReturnStmt target_9) {
		target_9.getExpr().(Literal).getValue()="0"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_9.getEnclosingFunction() = func
}

/*predicate func_10(Variable vret_2379, Variable vcheck_for_end_2385, ExprStmt target_18, EqualityOperation target_10) {
		target_10.getAnOperand().(VariableAccess).getTarget()=vret_2379
		and target_10.getAnOperand().(Literal).getValue()="0"
		and target_10.getParent().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vcheck_for_end_2385
		and target_10.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_18
}

*/
predicate func_11(Parameter vretarg_2377, Variable vp_2380, Variable vexpr_end_2381, Variable vcheck_for_end_2385, Variable vnl_2399, Function func, IfStmt target_11) {
		target_11.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("in_vim9script")
		and target_11.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vp_2380
		and target_11.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vexpr_end_2381
		and target_11.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vretarg_2377
		and target_11.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_11.getThen().(BlockStmt).getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_2380
		and target_11.getThen().(BlockStmt).getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="35"
		and target_11.getThen().(BlockStmt).getStmt(0).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnl_2399
		and target_11.getThen().(BlockStmt).getStmt(0).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_11.getThen().(BlockStmt).getStmt(0).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BreakStmt).toString() = "break;"
		and target_11.getThen().(BlockStmt).getStmt(0).(WhileStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_2380
		and target_11.getThen().(BlockStmt).getStmt(0).(WhileStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("skipwhite")
		and target_11.getThen().(BlockStmt).getStmt(0).(WhileStmt).getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcheck_for_end_2385
		and target_11.getThen().(BlockStmt).getStmt(0).(WhileStmt).getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_11.getThen().(BlockStmt).getStmt(1).(LabelStmt).toString() = "label ...:"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_11
}

/*predicate func_12(Variable vret_2379, Variable vcheck_for_end_2385, ExprStmt target_18, VariableAccess target_12) {
		target_12.getTarget()=vcheck_for_end_2385
		and target_12.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_2379
		and target_12.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_12.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_18
}

*/
predicate func_13(Variable vp_2380, LogicalAndExpr target_13) {
		target_13.getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_13.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(FunctionCall).getTarget().hasName("skipwhite")
		and target_13.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_2380
		and target_13.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_13.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="124"
		and target_13.getAnOperand() instanceof EqualityOperation
}

predicate func_14(Parameter veap_2375, Variable vcheck_for_end_2385, LogicalAndExpr target_14) {
		target_14.getAnOperand().(VariableAccess).getTarget()=vcheck_for_end_2385
		and target_14.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=veap_2375
		and target_14.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_15(Parameter vretarg_2377, Variable vp_2380, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vretarg_2377
		and target_15.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vp_2380
}

predicate func_16(Parameter veap_2375, Variable vp_2380, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nextcmd"
		and target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_2375
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("check_nextcmd")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_2380
}

predicate func_17(Parameter veap_2375, Variable vp_2380, BlockStmt target_17) {
		target_17.getStmt(0) instanceof IfStmt
		and target_17.getStmt(1) instanceof IfStmt
		and target_17.getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_17.getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(FunctionCall).getTarget().hasName("skipwhite")
		and target_17.getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_17.getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="124"
		and target_17.getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_17.getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nextcmd"
		and target_17.getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_2375
		and target_17.getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("check_nextcmd")
		and target_17.getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_2380
}

predicate func_18(Parameter varg_2373, Variable vp_2380, Variable vend_error_2386, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vend_error_2386
		and target_18.getExpr().(AssignExpr).getRValue().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ends_excmd2")
		and target_18.getExpr().(AssignExpr).getRValue().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=varg_2373
		and target_18.getExpr().(AssignExpr).getRValue().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_2380
}

from Function func, Parameter varg_2373, Parameter vrettv_2374, Parameter veap_2375, Parameter vretarg_2377, Variable vret_2379, Variable vp_2380, Variable vexpr_end_2381, Variable vdid_emsg_before_2382, Variable vdid_emsg, Variable vcalled_emsg_before_2383, Variable vcalled_emsg, Variable vflags_2384, Variable vcheck_for_end_2385, Variable vend_error_2386, Variable vnl_2399, Variable ve_trailing_characters_str, Variable ve_invalid_expression_str, ExprStmt target_2, ExprStmt target_3, LogicalOrExpr target_4, IfStmt target_5, IfStmt target_6, EqualityOperation target_8, ReturnStmt target_9, IfStmt target_11, LogicalAndExpr target_13, LogicalAndExpr target_14, ExprStmt target_15, ExprStmt target_16, BlockStmt target_17, ExprStmt target_18
where
not func_0(veap_2375, vp_2380, target_13, target_14, target_15)
and func_2(vp_2380, vexpr_end_2381, func, target_2)
and func_3(vp_2380, func, target_3)
and func_4(vret_2379, vend_error_2386, target_17, target_4)
and func_5(vrettv_2374, vret_2379, target_4, target_5)
and func_6(varg_2373, vp_2380, vdid_emsg_before_2382, vdid_emsg, vcalled_emsg_before_2383, vcalled_emsg, vflags_2384, vend_error_2386, ve_trailing_characters_str, ve_invalid_expression_str, target_4, target_6)
and func_8(veap_2375, vp_2380, target_16, target_8)
and func_9(target_4, func, target_9)
and func_11(vretarg_2377, vp_2380, vexpr_end_2381, vcheck_for_end_2385, vnl_2399, func, target_11)
and func_13(vp_2380, target_13)
and func_14(veap_2375, vcheck_for_end_2385, target_14)
and func_15(vretarg_2377, vp_2380, target_15)
and func_16(veap_2375, vp_2380, target_16)
and func_17(veap_2375, vp_2380, target_17)
and func_18(varg_2373, vp_2380, vend_error_2386, target_18)
and varg_2373.getType().hasName("char_u *")
and vrettv_2374.getType().hasName("typval_T *")
and veap_2375.getType().hasName("exarg_T *")
and vretarg_2377.getType().hasName("char_u **")
and vret_2379.getType().hasName("int")
and vp_2380.getType().hasName("char_u *")
and vexpr_end_2381.getType().hasName("char_u *")
and vdid_emsg_before_2382.getType().hasName("int")
and vdid_emsg.getType().hasName("int")
and vcalled_emsg_before_2383.getType().hasName("int")
and vcalled_emsg.getType().hasName("int")
and vflags_2384.getType().hasName("int")
and vcheck_for_end_2385.getType().hasName("int")
and vend_error_2386.getType().hasName("int")
and vnl_2399.getType().hasName("char_u *")
and ve_trailing_characters_str.getType() instanceof ArrayType
and ve_invalid_expression_str.getType() instanceof ArrayType
and varg_2373.getParentScope+() = func
and vrettv_2374.getParentScope+() = func
and veap_2375.getParentScope+() = func
and vretarg_2377.getParentScope+() = func
and vret_2379.getParentScope+() = func
and vp_2380.getParentScope+() = func
and vexpr_end_2381.getParentScope+() = func
and vdid_emsg_before_2382.getParentScope+() = func
and not vdid_emsg.getParentScope+() = func
and vcalled_emsg_before_2383.getParentScope+() = func
and not vcalled_emsg.getParentScope+() = func
and vflags_2384.getParentScope+() = func
and vcheck_for_end_2385.getParentScope+() = func
and vend_error_2386.getParentScope+() = func
and vnl_2399.getParentScope+() = func
and not ve_trailing_characters_str.getParentScope+() = func
and not ve_invalid_expression_str.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
