/**
 * @name imagemagick-948f1c86d649a29df08a38d2ff8b91cdf3e92b82-ReadBMPImage
 * @id cpp/imagemagick/948f1c86d649a29df08a38d2ff8b91cdf3e92b82/ReadBMPImage
 * @description imagemagick-948f1c86d649a29df08a38d2ff8b91cdf3e92b82-coders/bmp.c-ReadBMPImage CVE-2018-18024
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbmp_info_513, ValueFieldAccess target_0) {
		target_0.getTarget().getName()="ba_offset"
		and target_0.getQualifier().(VariableAccess).getTarget()=vbmp_info_513
}

predicate func_1(Variable vimage_516, Variable vstart_position_523, EqualityOperation target_3, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstart_position_523
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(FunctionCall).getTarget().hasName("TellBlob")
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_516
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_1.getParent().(IfStmt).getCondition()=target_3
}

predicate func_2(Function func, IfStmt target_2) {
		target_2.getCondition().(EqualityOperation).getAnOperand() instanceof ValueFieldAccess
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen() instanceof ExprStmt
		and target_2.getEnclosingFunction() = func
}

predicate func_3(EqualityOperation target_3) {
		target_3.getAnOperand() instanceof ValueFieldAccess
		and target_3.getAnOperand() instanceof Literal
}

from Function func, Variable vbmp_info_513, Variable vimage_516, Variable vstart_position_523, ValueFieldAccess target_0, ExprStmt target_1, IfStmt target_2, EqualityOperation target_3
where
func_0(vbmp_info_513, target_0)
and func_1(vimage_516, vstart_position_523, target_3, target_1)
and func_2(func, target_2)
and func_3(target_3)
and vbmp_info_513.getType().hasName("BMPInfo")
and vimage_516.getType().hasName("Image *")
and vstart_position_523.getType().hasName("MagickOffsetType")
and vbmp_info_513.getParentScope+() = func
and vimage_516.getParentScope+() = func
and vstart_position_523.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
