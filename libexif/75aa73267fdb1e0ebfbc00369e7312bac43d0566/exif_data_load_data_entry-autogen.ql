/**
 * @name libexif-75aa73267fdb1e0ebfbc00369e7312bac43d0566-exif_data_load_data_entry
 * @id cpp/libexif/75aa73267fdb1e0ebfbc00369e7312bac43d0566/exif-data-load-data-entry
 * @description libexif-75aa73267fdb1e0ebfbc00369e7312bac43d0566-libexif/exif-data.c-exif_data_load_data_entry CVE-2019-9278
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="Tag data past end of buffer (%u > %u)"
		and not target_0.getValue()="Tag data goes past end of buffer (%u > %u)"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vs_165, RelationalOperation target_18, VariableAccess target_1) {
		target_1.getTarget()=vs_165
		and target_18.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getLocation())
}

predicate func_2(Variable vs_165, VariableAccess target_2) {
		target_2.getTarget()=vs_165
}

predicate func_3(Variable vdoff_165, Parameter vsize_163, BlockStmt target_19, LogicalOrExpr target_17, ExprStmt target_20) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GEExpr or target_3 instanceof LEExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vdoff_165
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vsize_163
		and target_3.getParent().(IfStmt).getThen()=target_19
		and target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getGreaterOperand().(VariableAccess).getLocation())
		and target_3.getLesserOperand().(VariableAccess).getLocation().isBefore(target_20.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getLocation()))
}

predicate func_4(Variable vdoff_165, Parameter vdata_161, LogicalOrExpr target_17, ExprStmt target_21, ExprStmt target_22) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="priv"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_161
		and target_4.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifData"
		and target_4.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Tag starts past end of buffer (%u > %u)"
		and target_4.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vdoff_165
		and target_4.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getType().hasName("unsigned int")
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
		and target_21.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_5(Variable vdoff_165, Parameter vdata_161, Parameter vsize_163, Variable vs_165, LogicalOrExpr target_17, ExprStmt target_22, Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vs_165
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vdoff_165
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="priv"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_161
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifData"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Tag data goes past end of buffer (%u > %u)"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof AddExpr
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vsize_163
		and target_5.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_5)
		and target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_6(Variable vdoff_165, LogicalOrExpr target_17) {
	exists(SubExpr target_6 |
		target_6.getLeftOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_6.getRightOperand().(VariableAccess).getTarget()=vdoff_165
		and target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getRightOperand().(VariableAccess).getLocation()))
}

*/
/*predicate func_7(Parameter vdata_161, ExprStmt target_22) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="log"
		and target_7.getQualifier().(PointerFieldAccess).getTarget().getName()="priv"
		and target_7.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_161
		and target_7.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

*/
/*predicate func_8(LogicalOrExpr target_17, Function func) {
	exists(ReturnStmt target_8 |
		target_8.getExpr().(Literal).getValue()="0"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_8
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
		and target_8.getEnclosingFunction() = func)
}

*/
predicate func_9(Variable vdoff_165, Variable vs_165, AddExpr target_9) {
		target_9.getAnOperand().(VariableAccess).getTarget()=vdoff_165
		and target_9.getAnOperand().(VariableAccess).getTarget()=vs_165
}

predicate func_10(Variable vdoff_165, Parameter vdata_161, Parameter vsize_163, Variable vs_165, PointerFieldAccess target_10) {
		target_10.getTarget().getName()="log"
		and target_10.getQualifier().(PointerFieldAccess).getTarget().getName()="priv"
		and target_10.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_161
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifData"
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdoff_165
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_165
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vsize_163
}

predicate func_11(LogicalOrExpr target_17, Function func, ReturnStmt target_11) {
		target_11.getExpr().(Literal).getValue()="0"
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
		and target_11.getEnclosingFunction() = func
}

predicate func_12(Variable vdoff_165, VariableAccess target_12) {
		target_12.getTarget()=vdoff_165
}

predicate func_13(Variable vs_165, VariableAccess target_13) {
		target_13.getTarget()=vs_165
}

predicate func_14(Parameter vsize_163, VariableAccess target_14) {
		target_14.getTarget()=vsize_163
}

predicate func_15(Variable vdoff_165, VariableAccess target_15) {
		target_15.getTarget()=vdoff_165
}

predicate func_16(Variable vdoff_165, VariableAccess target_16) {
		target_16.getTarget()=vdoff_165
}

predicate func_17(Variable vdoff_165, Parameter vsize_163, Variable vs_165, BlockStmt target_19, LogicalOrExpr target_17) {
		target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdoff_165
		and target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_165
		and target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdoff_165
		and target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdoff_165
		and target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_165
		and target_17.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vs_165
		and target_17.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof AddExpr
		and target_17.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsize_163
		and target_17.getParent().(IfStmt).getThen()=target_19
}

predicate func_18(Variable vs_165, RelationalOperation target_18) {
		 (target_18 instanceof GTExpr or target_18 instanceof LTExpr)
		and target_18.getGreaterOperand().(VariableAccess).getTarget()=vs_165
		and target_18.getLesserOperand().(Literal).getValue()="4"
}

predicate func_19(Variable vdoff_165, Parameter vdata_161, Parameter vsize_163, Variable vs_165, BlockStmt target_19) {
		target_19.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_19.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_19.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="priv"
		and target_19.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_161
		and target_19.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifData"
		and target_19.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_19.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdoff_165
		and target_19.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_165
		and target_19.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vsize_163
}

predicate func_20(Variable vdoff_165, Parameter vdata_161, Parameter vsize_163, Variable vs_165, ExprStmt target_20) {
		target_20.getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_20.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_20.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="priv"
		and target_20.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_161
		and target_20.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifData"
		and target_20.getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_20.getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdoff_165
		and target_20.getExpr().(FunctionCall).getArgument(4).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vs_165
		and target_20.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vsize_163
}

predicate func_21(Variable vdoff_165, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdoff_165
		and target_21.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="8"
}

predicate func_22(Parameter vdata_161, Variable vs_165, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("exif_data_alloc")
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_161
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vs_165
}

from Function func, Variable vdoff_165, Parameter vdata_161, Parameter vsize_163, Variable vs_165, StringLiteral target_0, VariableAccess target_1, VariableAccess target_2, AddExpr target_9, PointerFieldAccess target_10, ReturnStmt target_11, VariableAccess target_12, VariableAccess target_13, VariableAccess target_14, VariableAccess target_15, VariableAccess target_16, LogicalOrExpr target_17, RelationalOperation target_18, BlockStmt target_19, ExprStmt target_20, ExprStmt target_21, ExprStmt target_22
where
func_0(func, target_0)
and func_1(vs_165, target_18, target_1)
and func_2(vs_165, target_2)
and not func_3(vdoff_165, vsize_163, target_19, target_17, target_20)
and not func_4(vdoff_165, vdata_161, target_17, target_21, target_22)
and not func_5(vdoff_165, vdata_161, vsize_163, vs_165, target_17, target_22, func)
and func_9(vdoff_165, vs_165, target_9)
and func_10(vdoff_165, vdata_161, vsize_163, vs_165, target_10)
and func_11(target_17, func, target_11)
and func_12(vdoff_165, target_12)
and func_13(vs_165, target_13)
and func_14(vsize_163, target_14)
and func_15(vdoff_165, target_15)
and func_16(vdoff_165, target_16)
and func_17(vdoff_165, vsize_163, vs_165, target_19, target_17)
and func_18(vs_165, target_18)
and func_19(vdoff_165, vdata_161, vsize_163, vs_165, target_19)
and func_20(vdoff_165, vdata_161, vsize_163, vs_165, target_20)
and func_21(vdoff_165, target_21)
and func_22(vdata_161, vs_165, target_22)
and vdoff_165.getType().hasName("unsigned int")
and vdata_161.getType().hasName("ExifData *")
and vsize_163.getType().hasName("unsigned int")
and vs_165.getType().hasName("unsigned int")
and vdoff_165.getParentScope+() = func
and vdata_161.getParentScope+() = func
and vsize_163.getParentScope+() = func
and vs_165.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
