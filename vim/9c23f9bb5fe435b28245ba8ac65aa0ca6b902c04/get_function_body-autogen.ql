/**
 * @name vim-9c23f9bb5fe435b28245ba8ac65aa0ca6b902c04-get_function_body
 * @id cpp/vim/9c23f9bb5fe435b28245ba8ac65aa0ca6b902c04/get-function-body
 * @description vim-9c23f9bb5fe435b28245ba8ac65aa0ca6b902c04-src/userfunc.c-get_function_body CVE-2021-4173
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vline_to_free_656, Parameter veap_653, BlockStmt target_9, ExprStmt target_10, ExprStmt target_11) {
	exists(EqualityOperation target_0 |
		target_0.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cmdlinep"
		and target_0.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_653
		and target_0.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vline_to_free_656
		and target_0.getParent().(IfStmt).getThen()=target_9
		and target_10.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vtheline_697, Parameter veap_653, EqualityOperation target_3, EqualityOperation target_12, LogicalOrExpr target_13, EqualityOperation target_14) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cmdlinep"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_653
		and target_1.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vtheline_697
		and target_1.getParent().(IfStmt).getCondition()=target_3
		and target_12.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vline_to_free_656, Parameter veap_653, LogicalAndExpr target_6, ExprStmt target_15, LogicalAndExpr target_16) {
	exists(IfStmt target_2 |
		target_2.getCondition().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cmdlinep"
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_653
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vline_to_free_656
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vim_free")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cmdlinep"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_653
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cmdlinep"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_653
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vline_to_free_656
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vline_to_free_656
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vskip_until_670, BlockStmt target_9, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vskip_until_670
		and target_3.getAnOperand().(Literal).getValue()="0"
		and target_3.getParent().(IfStmt).getThen()=target_9
}

predicate func_4(Variable vp_698, Variable vnesting_def_665, Variable vnesting_inline_666, Variable vnesting_667, BlockStmt target_17, ConditionalExpr target_4) {
		target_4.getCondition().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vnesting_inline_666
		and target_4.getCondition().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vnesting_667
		and target_4.getThen().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_698
		and target_4.getThen().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="125"
		and target_4.getElse().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("checkforcmd")
		and target_4.getElse().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp_698
		and target_4.getElse().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vnesting_def_665
		and target_4.getElse().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vnesting_667
		and target_4.getElse().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(StringLiteral).getValue()="enddef"
		and target_4.getElse().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getElse().(StringLiteral).getValue()="endfunction"
		and target_4.getElse().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="4"
		and target_4.getElse().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_698
		and target_4.getElse().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="58"
		and target_4.getParent().(IfStmt).getThen()=target_17
}

predicate func_5(Variable vnesting_667, BlockStmt target_18, EqualityOperation target_5) {
		target_5.getAnOperand().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vnesting_667
		and target_5.getAnOperand().(Literal).getValue()="0"
		and target_5.getParent().(IfStmt).getThen()=target_18
}

predicate func_6(Variable vnextcmd_816, BlockStmt target_19, LogicalAndExpr target_6) {
		target_6.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnextcmd_816
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("skipwhite")
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnextcmd_816
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getParent().(IfStmt).getThen()=target_19
}

predicate func_7(Variable vp_698, Variable ve_mismatched_endfunction, Variable ve_mismatched_enddef, Variable vnesting_def_665, Variable vnesting_667, Parameter veap_653, ConditionalExpr target_4, IfStmt target_7) {
		target_7.getCondition().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vnesting_def_665
		and target_7.getCondition().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vnesting_667
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("checkforcmd")
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp_698
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="endfunction"
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="4"
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_698
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="58"
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("emsg")
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("dcgettext")
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(VariableAccess).getTarget()=ve_mismatched_endfunction
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2).(Literal).getValue()="5"
		and target_7.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="cmdidx"
		and target_7.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_653
		and target_7.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("checkforcmd")
		and target_7.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp_698
		and target_7.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="enddef"
		and target_7.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="4"
		and target_7.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("emsg")
		and target_7.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("dcgettext")
		and target_7.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_7.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(VariableAccess).getTarget()=ve_mismatched_enddef
		and target_7.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2).(Literal).getValue()="5"
		and target_7.getParent().(IfStmt).getCondition()=target_4
}

predicate func_8(Parameter vline_to_free_656, BlockStmt target_20, EqualityOperation target_8) {
		target_8.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vline_to_free_656
		and target_8.getAnOperand().(Literal).getValue()="0"
		and target_8.getParent().(IfStmt).getThen()=target_20
}

predicate func_9(Variable vtheline_697, Variable vp_698, Variable vskip_until_670, BlockStmt target_9) {
		target_9.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("skipwhite")
		and target_9.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtheline_697
		and target_9.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_9.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtheline_697
		and target_9.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("strlen")
		and target_9.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_698
		and target_9.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vtheline_697
		and target_9.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_9.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_698
		and target_9.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vskip_until_670
		and target_9.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_9.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(DoStmt).getCondition().(Literal).getValue()="0"
}

predicate func_10(Variable vtheline_697, Parameter vline_to_free_656, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vline_to_free_656
		and target_10.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vtheline_697
}

predicate func_11(Parameter veap_653, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_sourced_lnum")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="getline"
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_653
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="cookie"
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_653
}

predicate func_12(Variable vtheline_697, EqualityOperation target_12) {
		target_12.getAnOperand().(VariableAccess).getTarget()=vtheline_697
		and target_12.getAnOperand().(Literal).getValue()="0"
}

predicate func_13(Variable vtheline_697, LogicalOrExpr target_13) {
		target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("skipwhite")
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtheline_697
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtheline_697
		and target_13.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_13.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtheline_697
		and target_13.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("strlen")
		and target_13.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_14(Parameter veap_653, EqualityOperation target_14) {
		target_14.getAnOperand().(PointerFieldAccess).getTarget().getName()="cmdidx"
		and target_14.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_653
}

predicate func_15(Variable vnextcmd_816, Parameter veap_653, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nextcmd"
		and target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_653
		and target_15.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnextcmd_816
}

predicate func_16(Variable vp_698, Parameter veap_653, LogicalAndExpr target_16) {
		target_16.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="cmdidx"
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_653
		and target_16.getAnOperand().(FunctionCall).getTarget().hasName("checkforcmd")
		and target_16.getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp_698
		and target_16.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="enddef"
		and target_16.getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="4"
}

predicate func_17(Variable vnextcmd_816, BlockStmt target_17) {
		target_17.getStmt(0).(IfStmt).getCondition() instanceof EqualityOperation
		and target_17.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="124"
		and target_17.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="125"
		and target_17.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnextcmd_816
		and target_17.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition() instanceof LogicalAndExpr
		and target_17.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition() instanceof EqualityOperation
}

predicate func_18(Variable vp_698, Variable vnextcmd_816, BlockStmt target_18) {
		target_18.getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_698
		and target_18.getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="124"
		and target_18.getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_698
		and target_18.getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="125"
		and target_18.getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnextcmd_816
		and target_18.getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_698
		and target_18.getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_18.getStmt(1).(IfStmt).getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_18.getStmt(1).(IfStmt).getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("skipwhite")
		and target_18.getStmt(1).(IfStmt).getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_18.getStmt(1).(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnextcmd_816
}

predicate func_19(Variable vnextcmd_816, Parameter vline_to_free_656, Parameter veap_653, BlockStmt target_19) {
		target_19.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nextcmd"
		and target_19.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_653
		and target_19.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnextcmd_816
		and target_19.getStmt(1).(IfStmt).getCondition() instanceof EqualityOperation
		and target_19.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vim_free")
		and target_19.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cmdlinep"
		and target_19.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cmdlinep"
		and target_19.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vline_to_free_656
		and target_19.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vline_to_free_656
		and target_19.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_20(Parameter vline_to_free_656, Parameter veap_653, BlockStmt target_20) {
		target_20.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vim_free")
		and target_20.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cmdlinep"
		and target_20.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_653
		and target_20.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cmdlinep"
		and target_20.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veap_653
		and target_20.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vline_to_free_656
}

from Function func, Variable vtheline_697, Variable vp_698, Variable vnextcmd_816, Variable ve_mismatched_endfunction, Variable ve_mismatched_enddef, Parameter vline_to_free_656, Variable vnesting_def_665, Variable vnesting_inline_666, Variable vnesting_667, Variable vskip_until_670, Parameter veap_653, EqualityOperation target_3, ConditionalExpr target_4, EqualityOperation target_5, LogicalAndExpr target_6, IfStmt target_7, EqualityOperation target_8, BlockStmt target_9, ExprStmt target_10, ExprStmt target_11, EqualityOperation target_12, LogicalOrExpr target_13, EqualityOperation target_14, ExprStmt target_15, LogicalAndExpr target_16, BlockStmt target_17, BlockStmt target_18, BlockStmt target_19, BlockStmt target_20
where
not func_0(vline_to_free_656, veap_653, target_9, target_10, target_11)
and not func_1(vtheline_697, veap_653, target_3, target_12, target_13, target_14)
and not func_2(vline_to_free_656, veap_653, target_6, target_15, target_16)
and func_3(vskip_until_670, target_9, target_3)
and func_4(vp_698, vnesting_def_665, vnesting_inline_666, vnesting_667, target_17, target_4)
and func_5(vnesting_667, target_18, target_5)
and func_6(vnextcmd_816, target_19, target_6)
and func_7(vp_698, ve_mismatched_endfunction, ve_mismatched_enddef, vnesting_def_665, vnesting_667, veap_653, target_4, target_7)
and func_8(vline_to_free_656, target_20, target_8)
and func_9(vtheline_697, vp_698, vskip_until_670, target_9)
and func_10(vtheline_697, vline_to_free_656, target_10)
and func_11(veap_653, target_11)
and func_12(vtheline_697, target_12)
and func_13(vtheline_697, target_13)
and func_14(veap_653, target_14)
and func_15(vnextcmd_816, veap_653, target_15)
and func_16(vp_698, veap_653, target_16)
and func_17(vnextcmd_816, target_17)
and func_18(vp_698, vnextcmd_816, target_18)
and func_19(vnextcmd_816, vline_to_free_656, veap_653, target_19)
and func_20(vline_to_free_656, veap_653, target_20)
and vtheline_697.getType().hasName("char_u *")
and vp_698.getType().hasName("char_u *")
and vnextcmd_816.getType().hasName("char_u *")
and ve_mismatched_endfunction.getType() instanceof ArrayType
and ve_mismatched_enddef.getType() instanceof ArrayType
and vline_to_free_656.getType().hasName("char_u **")
and vnesting_def_665.getType().hasName("char[50]")
and vnesting_inline_666.getType().hasName("char[50]")
and vnesting_667.getType().hasName("int")
and vskip_until_670.getType().hasName("char_u *")
and veap_653.getType().hasName("exarg_T *")
and vtheline_697.getParentScope+() = func
and vp_698.getParentScope+() = func
and vnextcmd_816.getParentScope+() = func
and not ve_mismatched_endfunction.getParentScope+() = func
and not ve_mismatched_enddef.getParentScope+() = func
and vline_to_free_656.getParentScope+() = func
and vnesting_def_665.getParentScope+() = func
and vnesting_inline_666.getParentScope+() = func
and vnesting_667.getParentScope+() = func
and vskip_until_670.getParentScope+() = func
and veap_653.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
