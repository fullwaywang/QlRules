/**
 * @name yara-10e8bd3071677dd1fa76beeef4bc2fc427cea5e7-hex_yyparse
 * @id cpp/yara/10e8bd3071677dd1fa76beeef4bc2fc427cea5e7/hex-yyparse
 * @description yara-10e8bd3071677dd1fa76beeef4bc2fc427cea5e7-libyara/hex_grammar.c-hex_yyparse CVE-2017-9438
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vyyscanner_1076, Parameter vlex_env_1076, FunctionCall target_15, ExprStmt target_16, ExprStmt target_17) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="levels"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("hex_yyget_extra")
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vyyscanner_1076
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="2000"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="last_error_code"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlex_env_1076
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="10"
		and target_0.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_0.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="yyabortlab"
		and target_15.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vyyscanner_1076, Parameter vlex_env_1076, ExprStmt target_17, ExprStmt target_18) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="levels"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("hex_yyget_extra")
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vyyscanner_1076
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="2000"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="last_error_code"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlex_env_1076
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="10"
		and target_1.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_1.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="yyabortlab"
		and target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_18.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vyyscanner_1076, Parameter vlex_env_1076, ExprStmt target_19, ExprStmt target_18, ExprStmt target_20) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="levels"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("hex_yyget_extra")
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vyyscanner_1076
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="2000"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="last_error_code"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlex_env_1076
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="10"
		and target_2.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_2.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="yyabortlab"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_19.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_18.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vyyscanner_1076, Parameter vlex_env_1076, FunctionCall target_21, ExprStmt target_22, ExprStmt target_23, ExprStmt target_24) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getGreaterOperand().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="levels"
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("hex_yyget_extra")
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vyyscanner_1076
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="2000"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="last_error_code"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlex_env_1076
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="10"
		and target_3.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_3.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="yyabortlab"
		and target_21.getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getCondition().(RelationalOperation).getGreaterOperand().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_22.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_23.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_24.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_8(Function func, EmptyStmt target_8) {
		target_8.toString() = ";"
		and target_8.getEnclosingFunction() = func
}

predicate func_9(Function func, EmptyStmt target_9) {
		target_9.toString() = ";"
		and target_9.getEnclosingFunction() = func
}

predicate func_10(Function func, EmptyStmt target_10) {
		target_10.toString() = ";"
		and target_10.getEnclosingFunction() = func
}

predicate func_11(Function func, EmptyStmt target_11) {
		target_11.toString() = ";"
		and target_11.getEnclosingFunction() = func
}

predicate func_12(Function func, EmptyStmt target_12) {
		target_12.toString() = ";"
		and target_12.getEnclosingFunction() = func
}

predicate func_13(Function func, EmptyStmt target_13) {
		target_13.toString() = ";"
		and target_13.getEnclosingFunction() = func
}

predicate func_14(Function func, EmptyStmt target_14) {
		target_14.toString() = ";"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14
}

predicate func_15(Parameter vyyscanner_1076, FunctionCall target_15) {
		target_15.getTarget().hasName("hex_yyget_extra")
		and target_15.getArgument(0).(VariableAccess).getTarget()=vyyscanner_1076
}

predicate func_16(Parameter vyyscanner_1076, Parameter vlex_env_1076, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("hex_yylex")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vyyscanner_1076
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlex_env_1076
}

predicate func_17(Parameter vlex_env_1076, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="last_error_code"
		and target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlex_env_1076
		and target_17.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_18(Parameter vlex_env_1076, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="last_error_code"
		and target_18.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlex_env_1076
		and target_18.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_19(Parameter vyyscanner_1076, Parameter vlex_env_1076, ExprStmt target_19) {
		target_19.getExpr().(FunctionCall).getTarget().hasName("hex_yyerror")
		and target_19.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vyyscanner_1076
		and target_19.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlex_env_1076
		and target_19.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="string too long"
}

predicate func_20(Parameter vlex_env_1076, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="last_error_code"
		and target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlex_env_1076
		and target_20.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_21(Parameter vyyscanner_1076, FunctionCall target_21) {
		target_21.getTarget().hasName("hex_yyget_extra")
		and target_21.getArgument(0).(VariableAccess).getTarget()=vyyscanner_1076
}

predicate func_22(Parameter vyyscanner_1076, Parameter vlex_env_1076, ExprStmt target_22) {
		target_22.getExpr().(FunctionCall).getTarget().hasName("hex_yyerror")
		and target_22.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vyyscanner_1076
		and target_22.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlex_env_1076
}

predicate func_23(Parameter vlex_env_1076, ExprStmt target_23) {
		target_23.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="last_error_code"
		and target_23.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlex_env_1076
		and target_23.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_24(Parameter vlex_env_1076, ExprStmt target_24) {
		target_24.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="last_error_code"
		and target_24.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlex_env_1076
		and target_24.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

from Function func, Parameter vyyscanner_1076, Parameter vlex_env_1076, EmptyStmt target_8, EmptyStmt target_9, EmptyStmt target_10, EmptyStmt target_11, EmptyStmt target_12, EmptyStmt target_13, EmptyStmt target_14, FunctionCall target_15, ExprStmt target_16, ExprStmt target_17, ExprStmt target_18, ExprStmt target_19, ExprStmt target_20, FunctionCall target_21, ExprStmt target_22, ExprStmt target_23, ExprStmt target_24
where
not func_0(vyyscanner_1076, vlex_env_1076, target_15, target_16, target_17)
and not func_1(vyyscanner_1076, vlex_env_1076, target_17, target_18)
and not func_2(vyyscanner_1076, vlex_env_1076, target_19, target_18, target_20)
and not func_3(vyyscanner_1076, vlex_env_1076, target_21, target_22, target_23, target_24)
and func_8(func, target_8)
and func_9(func, target_9)
and func_10(func, target_10)
and func_11(func, target_11)
and func_12(func, target_12)
and func_13(func, target_13)
and func_14(func, target_14)
and func_15(vyyscanner_1076, target_15)
and func_16(vyyscanner_1076, vlex_env_1076, target_16)
and func_17(vlex_env_1076, target_17)
and func_18(vlex_env_1076, target_18)
and func_19(vyyscanner_1076, vlex_env_1076, target_19)
and func_20(vlex_env_1076, target_20)
and func_21(vyyscanner_1076, target_21)
and func_22(vyyscanner_1076, vlex_env_1076, target_22)
and func_23(vlex_env_1076, target_23)
and func_24(vlex_env_1076, target_24)
and vyyscanner_1076.getType().hasName("void *")
and vlex_env_1076.getType().hasName("HEX_LEX_ENVIRONMENT *")
and vyyscanner_1076.getParentScope+() = func
and vlex_env_1076.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
