/**
 * @name yara-ab906da53ff2a68c6fd6d1fa73f2b7c7bf0bc636-yara_yyparse
 * @id cpp/yara/ab906da53ff2a68c6fd6d1fa73f2b7c7bf0bc636/yara-yyparse
 * @description yara-ab906da53ff2a68c6fd6d1fa73f2b7c7bf0bc636-libyara/grammar.c-yara_yyparse CVE-2017-5923
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(ValueFieldAccess target_29, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(CommaExpr).getLeftOperand().(SizeofExprOperator).getValue()="4"
		and target_0.getExpr().(CommaExpr).getRightOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition() instanceof Literal
		and target_0.getExpr().(CommaExpr).getRightOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen() instanceof EmptyStmt
		and target_0.getExpr().(CommaExpr).getRightOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__assert_fail")
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_29
		and target_0.getEnclosingFunction() = func)
}

/*predicate func_1(EqualityOperation target_9, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("__assert_fail")
		and target_1.getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_1.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_1.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_1.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getType().hasName("const char[13]")
		and target_1.getParent().(IfStmt).getCondition()=target_9
		and target_1.getEnclosingFunction() = func)
}

*/
predicate func_2(Parameter vcompiler_1404, ExprStmt target_30, EqualityOperation target_31) {
	exists(IfStmt target_2 |
		target_2.getCondition() instanceof EqualityOperation
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="last_result"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcompiler_1404
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="39"
		and target_2.getElse().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(ValueFieldAccess).getTarget().getName()="type"
		and target_2.getElse().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="expression"
		and target_2.getElse().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(0) instanceof SwitchCase
		and target_2.getElse().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_2.getElse().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(2) instanceof BreakStmt
		and target_2.getElse().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(3) instanceof SwitchCase
		and target_2.getElse().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(4) instanceof ExprStmt
		and target_2.getElse().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(5) instanceof BreakStmt
		and target_2.getElse().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(6) instanceof SwitchCase
		and target_2.getElse().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(7) instanceof ExprStmt
		and target_2.getElse().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(8) instanceof BreakStmt
		and target_2.getElse().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(9) instanceof SwitchCase
		and target_2.getElse().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(10) instanceof ExprStmt
		and target_2.getElse().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(11) instanceof BreakStmt
		and target_2.getElse().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(12) instanceof SwitchCase
		and target_2.getElse().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(13) instanceof ExprStmt
		and target_2.getElse().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(14) instanceof BreakStmt
		and target_2.getElse().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(15).(SwitchCase).toString() = "default: "
		and target_2.getElse().(BlockStmt).getStmt(0).(BlockStmt).getStmt(1).(LabelStmt).toString() = "label ...:"
		and target_30.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_31.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_4(ValueFieldAccess target_32, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(CommaExpr).getLeftOperand().(SizeofExprOperator).getValue()="4"
		and target_4.getExpr().(CommaExpr).getRightOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition() instanceof Literal
		and target_4.getExpr().(CommaExpr).getRightOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen() instanceof EmptyStmt
		and target_4.getExpr().(CommaExpr).getRightOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__assert_fail")
		and target_4.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_32
		and target_4.getEnclosingFunction() = func)
}

*/
predicate func_9(Variable vyyvsp_1438, BlockStmt target_33, EqualityOperation target_9) {
		target_9.getAnOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_9.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="c_string"
		and target_9.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vyyvsp_1438
		and target_9.getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getValue()="-2"
		and target_9.getAnOperand().(Literal).getValue()="128"
		and target_9.getParent().(IfStmt).getThen()=target_33
}

predicate func_10(Function func, SwitchCase target_10) {
		target_10.getExpr().(Literal).getValue()="2"
		and target_10.getEnclosingFunction() = func
}

predicate func_11(Variable vyyvsp_1438, ValueFieldAccess target_32, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("strlcat")
		and target_11.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="c_string"
		and target_11.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vyyvsp_1438
		and target_11.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getValue()="-2"
		and target_11.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="i"
		and target_11.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="128"
		and target_11.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_32
}

predicate func_12(Function func, SwitchCase target_12) {
		target_12.getExpr().(Literal).getValue()="32"
		and target_12.getEnclosingFunction() = func
}

predicate func_13(Variable vyyvsp_1438, ValueFieldAccess target_32, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("strlcat")
		and target_13.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="c_string"
		and target_13.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vyyvsp_1438
		and target_13.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getValue()="-2"
		and target_13.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="f"
		and target_13.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="128"
		and target_13.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_32
}

predicate func_14(Function func, SwitchCase target_14) {
		target_14.getExpr().(Literal).getValue()="1"
		and target_14.getEnclosingFunction() = func
}

predicate func_15(Variable vyyvsp_1438, ValueFieldAccess target_32, ExprStmt target_15) {
		target_15.getExpr().(FunctionCall).getTarget().hasName("strlcat")
		and target_15.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="c_string"
		and target_15.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vyyvsp_1438
		and target_15.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getValue()="-2"
		and target_15.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="b"
		and target_15.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="128"
		and target_15.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_32
}

predicate func_16(Function func, SwitchCase target_16) {
		target_16.getExpr().(Literal).getValue()="4"
		and target_16.getEnclosingFunction() = func
}

predicate func_17(Variable vyyvsp_1438, ValueFieldAccess target_32, ExprStmt target_17) {
		target_17.getExpr().(FunctionCall).getTarget().hasName("strlcat")
		and target_17.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="c_string"
		and target_17.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vyyvsp_1438
		and target_17.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getValue()="-2"
		and target_17.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="s"
		and target_17.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="128"
		and target_17.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_32
}

predicate func_18(Function func, SwitchCase target_18) {
		target_18.getExpr().(Literal).getValue()="8"
		and target_18.getEnclosingFunction() = func
}

predicate func_19(Variable vyyvsp_1438, ValueFieldAccess target_32, ExprStmt target_19) {
		target_19.getExpr().(FunctionCall).getTarget().hasName("strlcat")
		and target_19.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="c_string"
		and target_19.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vyyvsp_1438
		and target_19.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(UnaryMinusExpr).getValue()="-2"
		and target_19.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="r"
		and target_19.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="128"
		and target_19.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_32
}

predicate func_20(ValueFieldAccess target_32, Function func, BreakStmt target_20) {
		target_20.toString() = "break;"
		and target_20.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_32
		and target_20.getEnclosingFunction() = func
}

predicate func_21(ValueFieldAccess target_32, Function func, BreakStmt target_21) {
		target_21.toString() = "break;"
		and target_21.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_32
		and target_21.getEnclosingFunction() = func
}

predicate func_22(ValueFieldAccess target_32, Function func, BreakStmt target_22) {
		target_22.toString() = "break;"
		and target_22.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_32
		and target_22.getEnclosingFunction() = func
}

predicate func_23(ValueFieldAccess target_32, Function func, BreakStmt target_23) {
		target_23.toString() = "break;"
		and target_23.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_32
		and target_23.getEnclosingFunction() = func
}

predicate func_24(ValueFieldAccess target_32, Function func, BreakStmt target_24) {
		target_24.toString() = "break;"
		and target_24.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_32
		and target_24.getEnclosingFunction() = func
}

predicate func_25(Function func, EmptyStmt target_25) {
		target_25.toString() = ";"
		and target_25.getEnclosingFunction() = func
}

predicate func_26(Function func, SwitchCase target_26) {
		target_26.toString() = "default: "
		and target_26.getEnclosingFunction() = func
}

predicate func_27(Function func, EmptyStmt target_27) {
		target_27.toString() = ";"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_27
}

predicate func_28(Function func, EmptyStmt target_28) {
		target_28.toString() = ";"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_28
}

predicate func_29(Variable vyyvsp_1438, ValueFieldAccess target_29) {
		target_29.getTarget().getName()="type"
		and target_29.getQualifier().(ValueFieldAccess).getTarget().getName()="expression"
		and target_29.getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vyyvsp_1438
		and target_29.getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_30(Parameter vcompiler_1404, ExprStmt target_30) {
		target_30.getExpr().(FunctionCall).getTarget().hasName("yara_yyerror")
		and target_30.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcompiler_1404
		and target_30.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_31(Parameter vcompiler_1404, EqualityOperation target_31) {
		target_31.getAnOperand().(PointerFieldAccess).getTarget().getName()="last_result"
		and target_31.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcompiler_1404
		and target_31.getAnOperand().(Literal).getValue()="0"
}

predicate func_32(Variable vyyvsp_1438, ValueFieldAccess target_32) {
		target_32.getTarget().getName()="type"
		and target_32.getQualifier().(ValueFieldAccess).getTarget().getName()="expression"
		and target_32.getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vyyvsp_1438
		and target_32.getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_33(Parameter vcompiler_1404, BlockStmt target_33) {
		target_33.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="last_result"
		and target_33.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcompiler_1404
		and target_33.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="39"
}

from Function func, Parameter vcompiler_1404, Variable vyyvsp_1438, EqualityOperation target_9, SwitchCase target_10, ExprStmt target_11, SwitchCase target_12, ExprStmt target_13, SwitchCase target_14, ExprStmt target_15, SwitchCase target_16, ExprStmt target_17, SwitchCase target_18, ExprStmt target_19, BreakStmt target_20, BreakStmt target_21, BreakStmt target_22, BreakStmt target_23, BreakStmt target_24, EmptyStmt target_25, SwitchCase target_26, EmptyStmt target_27, EmptyStmt target_28, ValueFieldAccess target_29, ExprStmt target_30, EqualityOperation target_31, ValueFieldAccess target_32, BlockStmt target_33
where
not func_0(target_29, func)
and not func_2(vcompiler_1404, target_30, target_31)
and func_9(vyyvsp_1438, target_33, target_9)
and func_10(func, target_10)
and func_11(vyyvsp_1438, target_32, target_11)
and func_12(func, target_12)
and func_13(vyyvsp_1438, target_32, target_13)
and func_14(func, target_14)
and func_15(vyyvsp_1438, target_32, target_15)
and func_16(func, target_16)
and func_17(vyyvsp_1438, target_32, target_17)
and func_18(func, target_18)
and func_19(vyyvsp_1438, target_32, target_19)
and func_20(target_32, func, target_20)
and func_21(target_32, func, target_21)
and func_22(target_32, func, target_22)
and func_23(target_32, func, target_23)
and func_24(target_32, func, target_24)
and func_25(func, target_25)
and func_26(func, target_26)
and func_27(func, target_27)
and func_28(func, target_28)
and func_29(vyyvsp_1438, target_29)
and func_30(vcompiler_1404, target_30)
and func_31(vcompiler_1404, target_31)
and func_32(vyyvsp_1438, target_32)
and func_33(vcompiler_1404, target_33)
and vcompiler_1404.getType().hasName("YR_COMPILER *")
and vyyvsp_1438.getType().hasName("YYSTYPE *")
and vcompiler_1404.getParentScope+() = func
and vyyvsp_1438.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
