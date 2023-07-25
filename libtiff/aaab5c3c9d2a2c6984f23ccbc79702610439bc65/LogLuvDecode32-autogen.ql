/**
 * @name libtiff-aaab5c3c9d2a2c6984f23ccbc79702610439bc65-LogLuvDecode32
 * @id cpp/libtiff/aaab5c3c9d2a2c6984f23ccbc79702610439bc65/LogLuvDecode32
 * @description libtiff-aaab5c3c9d2a2c6984f23ccbc79702610439bc65-libtiff/tif_luv.c-LogLuvDecode32 NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsp_309, Variable vnpixels_312, ExprStmt target_13, MulExpr target_14, VariableAccess target_0) {
		target_0.getTarget()=vnpixels_312
		and target_0.getParent().(GEExpr).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="tbuflen"
		and target_0.getParent().(GEExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_309
		and target_0.getParent().(GEExpr).getParent().(IfStmt).getThen() instanceof EmptyStmt
		and target_0.getParent().(GEExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getLocation().isBefore(target_14.getLeftOperand().(VariableAccess).getLocation())
}

predicate func_1(Variable v__PRETTY_FUNCTION__, FunctionCall target_1) {
		target_1.getTarget().hasName("__assert_fail")
		and not target_1.getTarget().hasName("TIFFErrorExt")
		and target_1.getArgument(0).(StringLiteral).getValue()="sp->tbuflen >= npixels"
		and target_1.getArgument(1) instanceof StringLiteral
		and target_1.getArgument(2) instanceof Literal
		and target_1.getArgument(3).(VariableAccess).getTarget()=v__PRETTY_FUNCTION__
}

predicate func_2(Variable vsp_309, Variable vnpixels_312, EqualityOperation target_15, ExprStmt target_16) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(PointerFieldAccess).getTarget().getName()="tbuflen"
		and target_2.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_309
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vnpixels_312
		and target_2.getParent().(IfStmt).getThen() instanceof EmptyStmt
		and target_15.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vtif_306, ExprStmt target_17, ExprStmt target_18) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="tif_clientdata"
		and target_3.getQualifier().(VariableAccess).getTarget()=vtif_306
		and target_17.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getQualifier().(VariableAccess).getLocation())
		and target_3.getQualifier().(VariableAccess).getLocation().isBefore(target_18.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(RelationalOperation target_19, Function func) {
	exists(IfStmt target_6 |
		target_6.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("tmsize_t")
		and target_6.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Variable vsp_309, Variable vnpixels_312, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="tbuflen"
		and target_7.getQualifier().(VariableAccess).getTarget()=vsp_309
		and target_7.getParent().(GEExpr).getLesserOperand().(VariableAccess).getTarget()=vnpixels_312
}

/*predicate func_8(Variable vsp_309, Variable vnpixels_312, VariableAccess target_8) {
		target_8.getTarget()=vnpixels_312
		and target_8.getParent().(GEExpr).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="tbuflen"
		and target_8.getParent().(GEExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_309
}

*/
predicate func_9(Variable vsp_309, Variable vnpixels_312, CommaExpr target_9) {
		target_9.getLeftOperand().(SizeofExprOperator).getValue()="4"
		and target_9.getRightOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="tbuflen"
		and target_9.getRightOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_309
		and target_9.getRightOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnpixels_312
		and target_9.getRightOperand().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr() instanceof FunctionCall
}

/*predicate func_10(Variable vsp_309, Variable vnpixels_312, ExprStmt target_13, MulExpr target_14, RelationalOperation target_10) {
		 (target_10 instanceof GEExpr or target_10 instanceof LEExpr)
		and target_10.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="tbuflen"
		and target_10.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_309
		and target_10.getLesserOperand().(VariableAccess).getTarget()=vnpixels_312
		and target_10.getParent().(IfStmt).getThen() instanceof EmptyStmt
		and target_10.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_10.getLesserOperand().(VariableAccess).getLocation().isBefore(target_14.getLeftOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_11(RelationalOperation target_10, Function func, EmptyStmt target_11) {
		target_11.getParent().(IfStmt).getCondition()=target_10
		and target_11.getEnclosingFunction() = func
}

*/
/*predicate func_12(RelationalOperation target_10, Function func, ExprStmt target_12) {
		target_12.getExpr() instanceof FunctionCall
		and target_12.getParent().(IfStmt).getCondition()=target_10
		and target_12.getEnclosingFunction() = func
}

*/
predicate func_13(Variable vsp_309, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32 *")
		and target_13.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="tbuf"
		and target_13.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_309
}

predicate func_14(Variable vnpixels_312, MulExpr target_14) {
		target_14.getLeftOperand().(VariableAccess).getTarget()=vnpixels_312
		and target_14.getRightOperand().(SizeofExprOperator).getValue()="4"
}

predicate func_15(Variable vsp_309, EqualityOperation target_15) {
		target_15.getAnOperand().(PointerFieldAccess).getTarget().getName()="user_datafmt"
		and target_15.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_309
		and target_15.getAnOperand().(Literal).getValue()="2"
}

predicate func_16(Variable vsp_309, Variable vnpixels_312, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnpixels_312
		and target_16.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_16.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="pixel_size"
		and target_16.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_309
}

predicate func_17(Variable vsp_309, Parameter vtif_306, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsp_309
		and target_17.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="tif_data"
		and target_17.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_306
}

predicate func_18(Parameter vtif_306, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_18.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="tif_rawcp"
		and target_18.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_306
}

predicate func_19(RelationalOperation target_19) {
		 (target_19 instanceof GEExpr or target_19 instanceof LEExpr)
		and target_19.getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_19.getLesserOperand().(Literal).getValue()="128"
}

from Function func, Variable vsp_309, Variable vnpixels_312, Variable v__PRETTY_FUNCTION__, Parameter vtif_306, VariableAccess target_0, FunctionCall target_1, PointerFieldAccess target_7, CommaExpr target_9, ExprStmt target_13, MulExpr target_14, EqualityOperation target_15, ExprStmt target_16, ExprStmt target_17, ExprStmt target_18, RelationalOperation target_19
where
func_0(vsp_309, vnpixels_312, target_13, target_14, target_0)
and func_1(v__PRETTY_FUNCTION__, target_1)
and not func_2(vsp_309, vnpixels_312, target_15, target_16)
and not func_3(vtif_306, target_17, target_18)
and not func_6(target_19, func)
and func_7(vsp_309, vnpixels_312, target_7)
and func_9(vsp_309, vnpixels_312, target_9)
and func_13(vsp_309, target_13)
and func_14(vnpixels_312, target_14)
and func_15(vsp_309, target_15)
and func_16(vsp_309, vnpixels_312, target_16)
and func_17(vsp_309, vtif_306, target_17)
and func_18(vtif_306, target_18)
and func_19(target_19)
and vsp_309.getType().hasName("LogLuvState *")
and vnpixels_312.getType().hasName("tmsize_t")
and v__PRETTY_FUNCTION__.getType() instanceof ArrayType
and vtif_306.getType().hasName("TIFF *")
and vsp_309.(LocalVariable).getFunction() = func
and vnpixels_312.(LocalVariable).getFunction() = func
and not v__PRETTY_FUNCTION__.getParentScope+() = func
and vtif_306.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
