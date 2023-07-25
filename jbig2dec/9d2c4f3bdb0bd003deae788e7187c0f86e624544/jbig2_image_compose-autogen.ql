/**
 * @name jbig2dec-9d2c4f3bdb0bd003deae788e7187c0f86e624544-jbig2_image_compose
 * @id cpp/jbig2dec/9d2c4f3bdb0bd003deae788e7187c0f86e624544/jbig2-image-compose
 * @description jbig2dec-9d2c4f3bdb0bd003deae788e7187c0f86e624544-jbig2_image.c-jbig2_image_compose CVE-2016-9601
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdst_201, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="stride"
		and target_0.getQualifier().(VariableAccess).getTarget()=vdst_201
}

predicate func_1(Parameter vdst_201, Variable vleftbyte_205, Variable vd_208, LogicalOrExpr target_1) {
		target_1.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vd_208
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_201
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vleftbyte_205
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="stride"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_201
}

predicate func_2(Parameter vdst_201, Variable vh_204, Variable vleftbyte_205, Variable vd_208, BlockStmt target_3, LogicalOrExpr target_2) {
		target_2.getAnOperand() instanceof LogicalOrExpr
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vh_204
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="stride"
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_201
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vd_208
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vleftbyte_205
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vh_204
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="stride"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_201
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_201
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_201
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="stride"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_201
		and target_2.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_3
}

predicate func_3(BlockStmt target_3) {
		target_3.getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("jbig2_error")
		and target_3.getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(UnaryMinusExpr).getValue()="-1"
		and target_3.getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="preventing heap overflow in jbig2_image_compose"
}

from Function func, Parameter vdst_201, Variable vh_204, Variable vleftbyte_205, Variable vd_208, PointerFieldAccess target_0, LogicalOrExpr target_1, LogicalOrExpr target_2, BlockStmt target_3
where
func_0(vdst_201, target_0)
and func_1(vdst_201, vleftbyte_205, vd_208, target_1)
and func_2(vdst_201, vh_204, vleftbyte_205, vd_208, target_3, target_2)
and func_3(target_3)
and vdst_201.getType().hasName("Jbig2Image *")
and vh_204.getType().hasName("uint32_t")
and vleftbyte_205.getType().hasName("uint32_t")
and vd_208.getType().hasName("uint8_t *")
and vdst_201.getParentScope+() = func
and vh_204.getParentScope+() = func
and vleftbyte_205.getParentScope+() = func
and vd_208.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
