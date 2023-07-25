/**
 * @name libexif-75aa73267fdb1e0ebfbc00369e7312bac43d0566-exif_data_load_data_thumbnail
 * @id cpp/libexif/75aa73267fdb1e0ebfbc00369e7312bac43d0566/exif-data-load-data-thumbnail
 * @description libexif-75aa73267fdb1e0ebfbc00369e7312bac43d0566-libexif/exif-data.c-exif_data_load_data_thumbnail CVE-2019-9278
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="Bogus thumbnail offset (%u) or size (%u)."
		and not target_0.getValue()="Bogus thumbnail offset (%u)."
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vds_315, Parameter vo_315, BlockStmt target_15, LogicalOrExpr target_13) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vo_315
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vds_315
		and target_1.getParent().(IfStmt).getThen()=target_15
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vdata_314, Parameter vds_315, Parameter vo_315, Parameter vs_315, PointerFieldAccess target_16, IfStmt target_17, LogicalOrExpr target_13, NotExpr target_18, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vs_315
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vds_315
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vo_315
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="priv"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_314
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifData"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Bogus thumbnail size (%u), max would be %u."
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_315
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vds_315
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vo_315
		and target_2.getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_2)
		and target_16.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_18.getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

/*predicate func_3(Parameter vds_315, Parameter vo_315, LogicalOrExpr target_13) {
	exists(SubExpr target_3 |
		target_3.getLeftOperand().(VariableAccess).getTarget()=vds_315
		and target_3.getRightOperand().(VariableAccess).getTarget()=vo_315
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_3.getLeftOperand().(VariableAccess).getLocation()))
}

*/
predicate func_5(Parameter vo_315, VariableAccess target_5) {
		target_5.getTarget()=vo_315
}

predicate func_6(Parameter vs_315, VariableAccess target_6) {
		target_6.getTarget()=vs_315
}

predicate func_7(Parameter vds_315, VariableAccess target_7) {
		target_7.getTarget()=vds_315
}

predicate func_8(Parameter vdata_314, Parameter vo_315, Parameter vs_315, VariableAccess target_8) {
		target_8.getTarget()=vs_315
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="priv"
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_314
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifData"
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vo_315
}

predicate func_9(Function func, ReturnStmt target_9) {
		target_9.toString() = "return ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9
}

predicate func_10(Parameter vo_315, VariableAccess target_10) {
		target_10.getTarget()=vo_315
}

predicate func_11(Parameter vo_315, VariableAccess target_11) {
		target_11.getTarget()=vo_315
}

predicate func_12(Parameter vds_315, VariableAccess target_12) {
		target_12.getTarget()=vds_315
}

predicate func_13(Parameter vds_315, Parameter vo_315, Parameter vs_315, BlockStmt target_15, LogicalOrExpr target_13) {
		target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vo_315
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_315
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vo_315
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vo_315
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_315
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vs_315
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vo_315
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_315
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vds_315
		and target_13.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vo_315
		and target_13.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vds_315
		and target_13.getParent().(IfStmt).getThen()=target_15
}

/*predicate func_14(Parameter vo_315, Parameter vs_315, ExprStmt target_19, AddExpr target_14) {
		target_14.getAnOperand().(VariableAccess).getTarget()=vo_315
		and target_14.getAnOperand().(VariableAccess).getTarget()=vs_315
		and target_14.getAnOperand().(VariableAccess).getLocation().isBefore(target_19.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getLocation())
}

*/
predicate func_15(Parameter vdata_314, Parameter vo_315, Parameter vs_315, BlockStmt target_15) {
		target_15.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_15.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_15.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="priv"
		and target_15.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_314
		and target_15.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifData"
		and target_15.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_15.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vo_315
		and target_15.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vs_315
}

predicate func_16(Parameter vdata_314, PointerFieldAccess target_16) {
		target_16.getTarget().getName()="log"
		and target_16.getQualifier().(PointerFieldAccess).getTarget().getName()="priv"
		and target_16.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_314
}

predicate func_17(Parameter vdata_314, IfStmt target_17) {
		target_17.getCondition().(PointerFieldAccess).getTarget().getName()="data"
		and target_17.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_314
		and target_17.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_mem_free")
		and target_17.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="mem"
		and target_17.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="priv"
		and target_17.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_314
		and target_17.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="data"
		and target_17.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_314
}

predicate func_18(Parameter vdata_314, Parameter vs_315, NotExpr target_18) {
		target_18.getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_18.getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_314
		and target_18.getOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("exif_data_alloc")
		and target_18.getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_314
		and target_18.getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vs_315
}

predicate func_19(Parameter vdata_314, Parameter vo_315, Parameter vs_315, ExprStmt target_19) {
		target_19.getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_19.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_19.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="priv"
		and target_19.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_314
		and target_19.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifData"
		and target_19.getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_19.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vo_315
		and target_19.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vs_315
}

from Function func, Parameter vdata_314, Parameter vds_315, Parameter vo_315, Parameter vs_315, StringLiteral target_0, VariableAccess target_5, VariableAccess target_6, VariableAccess target_7, VariableAccess target_8, ReturnStmt target_9, VariableAccess target_10, VariableAccess target_11, VariableAccess target_12, LogicalOrExpr target_13, BlockStmt target_15, PointerFieldAccess target_16, IfStmt target_17, NotExpr target_18, ExprStmt target_19
where
func_0(func, target_0)
and not func_1(vds_315, vo_315, target_15, target_13)
and not func_2(vdata_314, vds_315, vo_315, vs_315, target_16, target_17, target_13, target_18, func)
and func_5(vo_315, target_5)
and func_6(vs_315, target_6)
and func_7(vds_315, target_7)
and func_8(vdata_314, vo_315, vs_315, target_8)
and func_9(func, target_9)
and func_10(vo_315, target_10)
and func_11(vo_315, target_11)
and func_12(vds_315, target_12)
and func_13(vds_315, vo_315, vs_315, target_15, target_13)
and func_15(vdata_314, vo_315, vs_315, target_15)
and func_16(vdata_314, target_16)
and func_17(vdata_314, target_17)
and func_18(vdata_314, vs_315, target_18)
and func_19(vdata_314, vo_315, vs_315, target_19)
and vdata_314.getType().hasName("ExifData *")
and vds_315.getType().hasName("unsigned int")
and vo_315.getType().hasName("ExifLong")
and vs_315.getType().hasName("ExifLong")
and vdata_314.getParentScope+() = func
and vds_315.getParentScope+() = func
and vo_315.getParentScope+() = func
and vs_315.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
