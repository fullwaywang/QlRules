/**
 * @name git-7360767e8dfc1895a932324079f7d45d7791d39f-handle_attr_line
 * @id cpp/git/7360767e8dfc1895a932324079f7d45d7791d39f/handle-attr-line
 * @description git-7360767e8dfc1895a932324079f7d45d7791d39f-attr.c-handle_attr_line CVE-2022-41953
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Function func) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("BUG_fl")
		and target_2.getArgument(0) instanceof StringLiteral
		and target_2.getArgument(1) instanceof Literal
		and target_2.getArgument(2).(StringLiteral).getValue()="negative growth in ALLOC_GROW_BY"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vres_652, RelationalOperation target_22) {
	exists(DoStmt target_3 |
		target_3.getCondition().(Literal).getValue()="0"
		and target_3.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("size_t")
		and target_3.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="alloc"
		and target_3.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
		and target_3.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand() instanceof DivExpr
		and target_3.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("size_t")
		and target_3.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getElse() instanceof ExprStmt
		and target_3.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_22)
}

predicate func_6(Parameter vres_652, FunctionCall target_23) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("memset")
		and target_6.getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="attrs"
		and target_6.getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
		and target_6.getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="num_matches"
		and target_6.getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
		and target_6.getArgument(1).(Literal).getValue()="0"
		and target_6.getArgument(2).(MulExpr).getValue()="8"
		and target_23.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_7(Parameter vres_652, RelationalOperation target_22, ExprStmt target_24) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="num_matches"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
		and target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("size_t")
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_7
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_22
		and target_24.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_8(Parameter vres_652, Variable va_658, NotExpr target_25, Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="attrs"
		and target_8.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
		and target_8.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="num_matches"
		and target_8.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
		and target_8.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand() instanceof Literal
		and target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=va_658
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_8)
		and target_25.getOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

/*predicate func_9(Parameter vres_652) {
	exists(SubExpr target_9 |
		target_9.getLeftOperand().(PointerFieldAccess).getTarget().getName()="num_matches"
		and target_9.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
		and target_9.getRightOperand() instanceof Literal
		and target_9.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="attrs"
		and target_9.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652)
}

*/
predicate func_10(Parameter vres_652, ExprStmt target_27, DivExpr target_10) {
		target_10.getLeftOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="alloc"
		and target_10.getLeftOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
		and target_10.getLeftOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="16"
		and target_10.getLeftOperand().(MulExpr).getRightOperand().(Literal).getValue()="3"
		and target_10.getRightOperand().(Literal).getValue()="2"
		and target_10.getParent().(LTExpr).getGreaterOperand() instanceof AddExpr
		and target_10.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_27
}

predicate func_11(Parameter vres_652, PointerFieldAccess target_11) {
		target_11.getTarget().getName()="num_matches"
		and target_11.getQualifier().(VariableAccess).getTarget()=vres_652
}

predicate func_12(Parameter vres_652, RelationalOperation target_28, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="alloc"
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
		and target_12.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="alloc"
		and target_12.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
		and target_12.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="16"
		and target_12.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(MulExpr).getRightOperand().(Literal).getValue()="3"
		and target_12.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(Literal).getValue()="2"
		and target_12.getParent().(IfStmt).getCondition()=target_28
}

predicate func_13(Parameter vres_652, RelationalOperation target_22, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="attrs"
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xrealloc")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="attrs"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("st_mult")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(SizeofExprOperator).getValue()="8"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="alloc"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_22
}

predicate func_14(Parameter vres_652, BlockStmt target_29, AddExpr target_14) {
		target_14.getAnOperand().(PointerFieldAccess).getTarget().getName()="num_matches"
		and target_14.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
		and target_14.getAnOperand().(Literal).getValue()="1"
		and target_14.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getTarget().getName()="alloc"
		and target_14.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
		and target_14.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_29
}

predicate func_15(Parameter vres_652, PointerFieldAccess target_15) {
		target_15.getTarget().getName()="num_matches"
		and target_15.getQualifier().(VariableAccess).getTarget()=vres_652
}

predicate func_16(Parameter vres_652, PointerFieldAccess target_16) {
		target_16.getTarget().getName()="num_matches"
		and target_16.getQualifier().(VariableAccess).getTarget()=vres_652
}

predicate func_19(Parameter vres_652, ExprStmt target_27, AddExpr target_19) {
		target_19.getAnOperand().(PointerFieldAccess).getTarget().getName()="num_matches"
		and target_19.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
		and target_19.getAnOperand() instanceof Literal
		and target_19.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_27
}

predicate func_20(Parameter vres_652, AddExpr target_20) {
		target_20.getAnOperand().(PointerFieldAccess).getTarget().getName()="num_matches"
		and target_20.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
		and target_20.getAnOperand() instanceof Literal
		and target_20.getParent().(AssignExpr).getRValue() = target_20
		and target_20.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="alloc"
		and target_20.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
}

predicate func_21(Parameter vres_652, PostfixIncrExpr target_21) {
		target_21.getOperand().(PointerFieldAccess).getTarget().getName()="num_matches"
		and target_21.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
		and target_21.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="attrs"
		and target_21.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
}

predicate func_22(Parameter vres_652, RelationalOperation target_22) {
		 (target_22 instanceof GTExpr or target_22 instanceof LTExpr)
		and target_22.getGreaterOperand() instanceof AddExpr
		and target_22.getLesserOperand().(PointerFieldAccess).getTarget().getName()="alloc"
		and target_22.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
}

predicate func_23(Parameter vres_652, FunctionCall target_23) {
		target_23.getTarget().hasName("st_mult")
		and target_23.getArgument(0).(SizeofExprOperator).getValue()="8"
		and target_23.getArgument(1).(PointerFieldAccess).getTarget().getName()="alloc"
		and target_23.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
}

predicate func_24(Parameter vres_652, Variable va_658, ExprStmt target_24) {
		target_24.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="attrs"
		and target_24.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
		and target_24.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset() instanceof PostfixIncrExpr
		and target_24.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=va_658
}

predicate func_25(Variable va_658, NotExpr target_25) {
		target_25.getOperand().(VariableAccess).getTarget()=va_658
}

predicate func_27(Parameter vres_652, ExprStmt target_27) {
		target_27.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="alloc"
		and target_27.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
		and target_27.getExpr().(AssignExpr).getRValue() instanceof AddExpr
}

predicate func_28(RelationalOperation target_28) {
		 (target_28 instanceof GTExpr or target_28 instanceof LTExpr)
		and target_28.getLesserOperand() instanceof DivExpr
		and target_28.getGreaterOperand() instanceof AddExpr
}

predicate func_29(Parameter vres_652, BlockStmt target_29) {
		target_29.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand() instanceof DivExpr
		and target_29.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_29.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="alloc"
		and target_29.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_652
		and target_29.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof AddExpr
		and target_29.getStmt(0).(IfStmt).getElse() instanceof ExprStmt
}

from Function func, Parameter vres_652, Variable va_658, DivExpr target_10, PointerFieldAccess target_11, ExprStmt target_12, ExprStmt target_13, AddExpr target_14, PointerFieldAccess target_15, PointerFieldAccess target_16, AddExpr target_19, AddExpr target_20, PostfixIncrExpr target_21, RelationalOperation target_22, FunctionCall target_23, ExprStmt target_24, NotExpr target_25, ExprStmt target_27, RelationalOperation target_28, BlockStmt target_29
where
not func_2(func)
and not func_3(vres_652, target_22)
and not func_6(vres_652, target_23)
and not func_7(vres_652, target_22, target_24)
and not func_8(vres_652, va_658, target_25, func)
and func_10(vres_652, target_27, target_10)
and func_11(vres_652, target_11)
and func_12(vres_652, target_28, target_12)
and func_13(vres_652, target_22, target_13)
and func_14(vres_652, target_29, target_14)
and func_15(vres_652, target_15)
and func_16(vres_652, target_16)
and func_19(vres_652, target_27, target_19)
and func_20(vres_652, target_20)
and func_21(vres_652, target_21)
and func_22(vres_652, target_22)
and func_23(vres_652, target_23)
and func_24(vres_652, va_658, target_24)
and func_25(va_658, target_25)
and func_27(vres_652, target_27)
and func_28(target_28)
and func_29(vres_652, target_29)
and vres_652.getType().hasName("attr_stack *")
and va_658.getType().hasName("match_attr *")
and vres_652.getParentScope+() = func
and va_658.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
