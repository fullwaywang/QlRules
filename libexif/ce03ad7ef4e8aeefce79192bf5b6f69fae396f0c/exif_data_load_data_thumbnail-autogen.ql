/**
 * @name libexif-ce03ad7ef4e8aeefce79192bf5b6f69fae396f0c-exif_data_load_data_thumbnail
 * @id cpp/libexif/ce03ad7ef4e8aeefce79192bf5b6f69fae396f0c/exif-data-load-data-thumbnail
 * @description libexif-ce03ad7ef4e8aeefce79192bf5b6f69fae396f0c-libexif/exif-data.c-exif_data_load_data_thumbnail CVE-2020-0198
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_323, BlockStmt target_5, VariableAccess target_0) {
		target_0.getTarget()=vs_323
		and target_0.getParent().(GTExpr).getLesserOperand() instanceof SubExpr
		and target_0.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_5
}

predicate func_1(Parameter vo_323, SubExpr target_6, VariableAccess target_1) {
		target_1.getTarget()=vo_323
		and target_1.getLocation().isBefore(target_6.getRightOperand().(VariableAccess).getLocation())
}

predicate func_2(Parameter vds_323, Parameter vo_323, Parameter vs_323, BlockStmt target_5, RelationalOperation target_7, SubExpr target_6, ExprStmt target_8, RelationalOperation target_10) {
	exists(LogicalOrExpr target_2 |
		target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vo_323
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vds_323
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vs_323
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vds_323
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("ExifLong")
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vds_323
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getType().hasName("ExifLong")
		and target_2.getParent().(IfStmt).getThen()=target_5
		and target_7.getLesserOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_6.getLeftOperand().(VariableAccess).getLocation())
		and target_8.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_10.getGreaterOperand().(VariableAccess).getLocation()))
}

/*predicate func_3(Parameter vds_323, Parameter vs_323, BlockStmt target_5, SubExpr target_6) {
	exists(SubExpr target_3 |
		target_3.getLeftOperand().(VariableAccess).getTarget()=vds_323
		and target_3.getRightOperand().(VariableAccess).getType().hasName("ExifLong")
		and target_3.getParent().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vs_323
		and target_3.getParent().(GTExpr).getLesserOperand() instanceof SubExpr
		and target_3.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_5
		and target_3.getLeftOperand().(VariableAccess).getLocation().isBefore(target_6.getLeftOperand().(VariableAccess).getLocation()))
}

*/
predicate func_4(Parameter vds_323, Parameter vo_323, Parameter vs_323, BlockStmt target_5, SubExpr target_4) {
		target_4.getLeftOperand().(VariableAccess).getTarget()=vds_323
		and target_4.getRightOperand().(VariableAccess).getTarget()=vo_323
		and target_4.getParent().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vs_323
		and target_4.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_5
}

predicate func_5(Parameter vds_323, Parameter vo_323, Parameter vs_323, BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="priv"
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifData"
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Bogus thumbnail size (%u), max would be %u."
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_323
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vds_323
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vo_323
}

predicate func_6(Parameter vds_323, Parameter vo_323, SubExpr target_6) {
		target_6.getLeftOperand().(VariableAccess).getTarget()=vds_323
		and target_6.getRightOperand().(VariableAccess).getTarget()=vo_323
}

predicate func_7(Parameter vds_323, Parameter vo_323, RelationalOperation target_7) {
		 (target_7 instanceof GEExpr or target_7 instanceof LEExpr)
		and target_7.getGreaterOperand().(VariableAccess).getTarget()=vo_323
		and target_7.getLesserOperand().(VariableAccess).getTarget()=vds_323
}

predicate func_8(Parameter vo_323, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="priv"
		and target_8.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifData"
		and target_8.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Bogus thumbnail offset (%u)."
		and target_8.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vo_323
}

predicate func_10(Parameter vs_323, RelationalOperation target_10) {
		 (target_10 instanceof GTExpr or target_10 instanceof LTExpr)
		and target_10.getGreaterOperand().(VariableAccess).getTarget()=vs_323
		and target_10.getLesserOperand() instanceof SubExpr
}

from Function func, Parameter vds_323, Parameter vo_323, Parameter vs_323, VariableAccess target_0, VariableAccess target_1, SubExpr target_4, BlockStmt target_5, SubExpr target_6, RelationalOperation target_7, ExprStmt target_8, RelationalOperation target_10
where
func_0(vs_323, target_5, target_0)
and func_1(vo_323, target_6, target_1)
and not func_2(vds_323, vo_323, vs_323, target_5, target_7, target_6, target_8, target_10)
and func_4(vds_323, vo_323, vs_323, target_5, target_4)
and func_5(vds_323, vo_323, vs_323, target_5)
and func_6(vds_323, vo_323, target_6)
and func_7(vds_323, vo_323, target_7)
and func_8(vo_323, target_8)
and func_10(vs_323, target_10)
and vds_323.getType().hasName("unsigned int")
and vo_323.getType().hasName("ExifLong")
and vs_323.getType().hasName("ExifLong")
and vds_323.getParentScope+() = func
and vo_323.getParentScope+() = func
and vs_323.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
