/**
 * @name libplist-3a55ddd3c4c11ce75a86afbefd085d8d397ff957-base64decode
 * @id cpp/libplist/3a55ddd3c4c11ce75a86afbefd085d8d397ff957/base64decode
 * @description libplist-3a55ddd3c4c11ce75a86afbefd085d8d397ff957-src/base64.c-base64decode CVE-2017-5209
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Initializer target_0) {
		target_0.getExpr().(Literal).getValue()="0"
		and target_0.getExpr().getEnclosingFunction() = func
}

predicate func_1(Variable vp_113, VariableAccess target_1) {
		target_1.getTarget()=vp_113
}

predicate func_7(Variable vptr_112) {
	exists(WhileStmt target_7 |
		target_7.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vptr_112
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="32"
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="9"
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_112
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="10"
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_112
		and target_7.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="13"
		and target_7.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vptr_112)
}

/*predicate func_8(Variable vptr_112, BlockStmt target_38, LogicalOrExpr target_40) {
	exists(RelationalOperation target_8 |
		 (target_8 instanceof GTExpr or target_8 instanceof LTExpr)
		and target_8.getLesserOperand().(VariableAccess).getTarget()=vptr_112
		and target_8.getGreaterOperand() instanceof PointerArithmeticOperation
		and target_8.getParent().(LogicalAndExpr).getAnOperand() instanceof RelationalOperation
		and target_8.getParent().(LogicalAndExpr).getAnOperand() instanceof RelationalOperation
		and target_8.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_38
		and target_8.getLesserOperand().(VariableAccess).getLocation().isBefore(target_40.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

*/
/*predicate func_9(Variable vptr_112, BlockStmt target_38, LogicalOrExpr target_40) {
	exists(LogicalOrExpr target_9 |
		target_9.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_112
		and target_9.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="32"
		and target_9.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_112
		and target_9.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="9"
		and target_9.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_112
		and target_9.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="10"
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_112
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="13"
		and target_9.getParent().(LogicalAndExpr).getAnOperand() instanceof RelationalOperation
		and target_9.getParent().(LogicalAndExpr).getAnOperand() instanceof RelationalOperation
		and target_9.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_38
		and target_40.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_9.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

*/
/*predicate func_10(Variable vptr_112) {
	exists(PostfixIncrExpr target_10 |
		target_10.getOperand().(VariableAccess).getTarget()=vptr_112)
}

*/
predicate func_11(Variable vptr_112, BlockStmt target_38) {
	exists(EqualityOperation target_11 |
		target_11.getAnOperand().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_11.getAnOperand().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("const signed char[256]")
		and target_11.getAnOperand().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vptr_112
		and target_11.getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_11.getParent().(IfStmt).getThen()=target_38)
}

predicate func_12(LogicalAndExpr target_43, Function func) {
	exists(ContinueStmt target_12 |
		target_12.toString() = "continue;"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_12
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_43
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(Function func) {
	exists(AssignExpr target_13 |
		target_13.getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("int[4]")
		and target_13.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_13.getRValue().(VariableAccess).getType().hasName("int")
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(Function func) {
	exists(IfStmt target_14 |
		target_14.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_14.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_14.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_14.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("int[4]")
		and target_14.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_14.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_14.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("int[4]")
		and target_14.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_14.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_14.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("int[4]")
		and target_14.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_14.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_14.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("int[4]")
		and target_14.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_14.getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_14.getThen().(BlockStmt).getStmt(5).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_14.getThen().(BlockStmt).getStmt(6).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_14.getThen().(BlockStmt).getStmt(6).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_14.getThen().(BlockStmt).getStmt(7).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_14.getThen().(BlockStmt).getStmt(7).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_14.getEnclosingFunction() = func)
}

/*predicate func_15(Function func) {
	exists(AssignExpr target_15 |
		target_15.getLValue().(VariableAccess).getType().hasName("int")
		and target_15.getRValue().(Literal).getValue()="0"
		and target_15.getEnclosingFunction() = func)
}

*/
/*predicate func_16(Function func) {
	exists(AssignExpr target_16 |
		target_16.getLValue().(VariableAccess).getType().hasName("int")
		and target_16.getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("int[4]")
		and target_16.getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_16.getEnclosingFunction() = func)
}

*/
predicate func_18(Parameter vbuf_106, Variable vlen_109, PointerArithmeticOperation target_18) {
		target_18.getAnOperand().(VariableAccess).getTarget()=vbuf_106
		and target_18.getAnOperand().(VariableAccess).getTarget()=vlen_109
}

predicate func_19(Variable vptr_112, VariableAccess target_19) {
		target_19.getTarget()=vptr_112
}

predicate func_20(Variable vptr_112, VariableAccess target_20) {
		target_20.getTarget()=vptr_112
		and target_20.getParent().(FunctionCall).getParent().(AssignPointerAddExpr).getRValue() instanceof FunctionCall
}

predicate func_21(Variable vptr_112, VariableAccess target_21) {
		target_21.getTarget()=vptr_112
		and target_21.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_23(Variable vptr_112, VariableAccess target_23) {
		target_23.getTarget()=vptr_112
}

predicate func_24(Variable vp_113, VariableAccess target_24) {
		target_24.getTarget()=vp_113
		and target_24.getParent().(AssignAddExpr).getLValue() = target_24
		and target_24.getParent().(AssignAddExpr).getRValue() instanceof FunctionCall
}

predicate func_25(Variable voutbuf_111, VariableAccess target_25) {
		target_25.getTarget()=voutbuf_111
}

predicate func_26(Variable vptr_112, VariableAccess target_26) {
		target_26.getTarget()=vptr_112
		and target_26.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue() instanceof FunctionCall
}

predicate func_27(Variable vptr_112, VariableAccess target_27) {
		target_27.getTarget()=vptr_112
}

predicate func_28(Function func, LabelStmt target_28) {
		target_28.toString() = "label ...:"
		and target_28.getEnclosingFunction() = func
}

predicate func_30(Variable vptr_112, AssignPointerAddExpr target_30) {
		target_30.getLValue().(VariableAccess).getTarget()=vptr_112
		and target_30.getRValue().(FunctionCall).getTarget().hasName("strspn")
		and target_30.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vptr_112
		and target_30.getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="\r\n\t "
}

predicate func_31(Variable vptr_112, Variable vl_114, AssignExpr target_31) {
		target_31.getLValue().(VariableAccess).getTarget()=vl_114
		and target_31.getRValue().(FunctionCall).getTarget().hasName("strcspn")
		and target_31.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vptr_112
		and target_31.getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="\r\n\t "
}

/*predicate func_32(Variable vptr_112, Variable vl_114, BlockStmt target_38, RelationalOperation target_32) {
		 (target_32 instanceof GTExpr or target_32 instanceof LTExpr)
		and target_32.getGreaterOperand().(VariableAccess).getTarget()=vl_114
		and target_32.getLesserOperand() instanceof Literal
		and target_32.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vptr_112
		and target_32.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vl_114
		and target_32.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_32.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_38
}

*/
/*predicate func_33(Variable vptr_112, Variable vl_114, BlockStmt target_38, RelationalOperation target_33) {
		 (target_33 instanceof GEExpr or target_33 instanceof LEExpr)
		and target_33.getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vptr_112
		and target_33.getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vl_114
		and target_33.getGreaterOperand() instanceof PointerArithmeticOperation
		and target_33.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vl_114
		and target_33.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_33.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_38
}

*/
predicate func_34(Variable voutbuf_111, Variable vptr_112, Variable vp_113, Variable vl_114, AssignAddExpr target_34) {
		target_34.getLValue().(VariableAccess).getTarget()=vp_113
		and target_34.getRValue().(FunctionCall).getTarget().hasName("base64decode_block")
		and target_34.getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voutbuf_111
		and target_34.getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_113
		and target_34.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vptr_112
		and target_34.getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vl_114
}

predicate func_35(Variable vptr_112, Variable vl_114, AssignPointerAddExpr target_35) {
		target_35.getLValue().(VariableAccess).getTarget()=vptr_112
		and target_35.getRValue().(VariableAccess).getTarget()=vl_114
}

predicate func_36(LogicalAndExpr target_43, Function func, BreakStmt target_36) {
		target_36.toString() = "break;"
		and target_36.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_43
		and target_36.getEnclosingFunction() = func
}

predicate func_38(BlockStmt target_38) {
		target_38.getStmt(0).(ExprStmt).getExpr() instanceof AssignAddExpr
		and target_38.getStmt(1).(ExprStmt).getExpr() instanceof AssignPointerAddExpr
}

predicate func_40(Parameter vbuf_106, Variable vlen_109, Variable vptr_112, LogicalOrExpr target_40) {
		target_40.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_112
		and target_40.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_40.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vptr_112
		and target_40.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_106
		and target_40.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlen_109
}

predicate func_43(LogicalAndExpr target_43) {
		target_43.getAnOperand() instanceof RelationalOperation
		and target_43.getAnOperand() instanceof RelationalOperation
}

from Function func, Parameter vbuf_106, Variable vlen_109, Variable voutbuf_111, Variable vptr_112, Variable vp_113, Variable vl_114, Initializer target_0, VariableAccess target_1, PointerArithmeticOperation target_18, VariableAccess target_19, VariableAccess target_20, VariableAccess target_21, VariableAccess target_23, VariableAccess target_24, VariableAccess target_25, VariableAccess target_26, VariableAccess target_27, LabelStmt target_28, AssignPointerAddExpr target_30, AssignExpr target_31, AssignAddExpr target_34, AssignPointerAddExpr target_35, BreakStmt target_36, BlockStmt target_38, LogicalOrExpr target_40, LogicalAndExpr target_43
where
func_0(func, target_0)
and func_1(vp_113, target_1)
and not func_7(vptr_112)
and not func_11(vptr_112, target_38)
and not func_12(target_43, func)
and not func_13(func)
and not func_14(func)
and func_18(vbuf_106, vlen_109, target_18)
and func_19(vptr_112, target_19)
and func_20(vptr_112, target_20)
and func_21(vptr_112, target_21)
and func_23(vptr_112, target_23)
and func_24(vp_113, target_24)
and func_25(voutbuf_111, target_25)
and func_26(vptr_112, target_26)
and func_27(vptr_112, target_27)
and func_28(func, target_28)
and func_30(vptr_112, target_30)
and func_31(vptr_112, vl_114, target_31)
and func_34(voutbuf_111, vptr_112, vp_113, vl_114, target_34)
and func_35(vptr_112, vl_114, target_35)
and func_36(target_43, func, target_36)
and func_38(target_38)
and func_40(vbuf_106, vlen_109, vptr_112, target_40)
and func_43(target_43)
and vbuf_106.getType().hasName("const char *")
and vlen_109.getType().hasName("size_t")
and voutbuf_111.getType().hasName("unsigned char *")
and vptr_112.getType().hasName("const char *")
and vp_113.getType().hasName("int")
and vl_114.getType().hasName("size_t")
and vbuf_106.getParentScope+() = func
and vlen_109.getParentScope+() = func
and voutbuf_111.getParentScope+() = func
and vptr_112.getParentScope+() = func
and vp_113.getParentScope+() = func
and vl_114.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
