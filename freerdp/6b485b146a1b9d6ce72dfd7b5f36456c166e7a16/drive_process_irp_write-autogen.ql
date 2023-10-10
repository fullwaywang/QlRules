/**
 * @name freerdp-6b485b146a1b9d6ce72dfd7b5f36456c166e7a16-drive_process_irp_write
 * @id cpp/freerdp/6b485b146a1b9d6ce72dfd7b5f36456c166e7a16/drive-process-irp-write
 * @description freerdp-6b485b146a1b9d6ce72dfd7b5f36456c166e7a16-channels/drive/client/drive_main.c-drive_process_irp_write CVE-2020-11089
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("void *")
		and target_0.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0))
}

predicate func_1(Parameter virp_329, Variable vLength_332, ExprStmt target_8, FunctionCall target_7, ExprStmt target_9, NotExpr target_10) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("Stream_SafeSeek")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_329
		and target_1.getArgument(1).(VariableAccess).getTarget()=vLength_332
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getArgument(1).(VariableAccess).getLocation())
		and target_1.getArgument(1).(VariableAccess).getLocation().isBefore(target_10.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_2(NotExpr target_6, Function func) {
	exists(ReturnStmt target_2 |
		target_2.getExpr().(Literal).getValue()="13"
		and target_2.getParent().(IfStmt).getCondition()=target_6
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter virp_329, Variable vfile_331, Variable vLength_332, Variable vOffset_333, ExprStmt target_11, NotExpr target_6, ExprStmt target_12, ExprStmt target_13, ExprStmt target_14, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition() instanceof NotExpr
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="IoStatus"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_329
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="3221225473"
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vLength_332
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("drive_file_seek")
		and target_3.getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfile_331
		and target_3.getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vOffset_333
		and target_3.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="IoStatus"
		and target_3.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_329
		and target_3.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("drive_map_windows_err")
		and target_3.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("GetLastError")
		and target_3.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vLength_332
		and target_3.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("drive_file_write")
		and target_3.getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfile_331
		and target_3.getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("void *")
		and target_3.getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vLength_332
		and target_3.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="IoStatus"
		and target_3.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("drive_map_windows_err")
		and target_3.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vLength_332
		and target_3.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_3)
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getOperand().(VariableAccess).getLocation().isBefore(target_3.getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_13.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

/*predicate func_4(Variable vfile_331, Variable vLength_332, BlockStmt target_15, NotExpr target_16) {
	exists(NotExpr target_4 |
		target_4.getOperand().(FunctionCall).getTarget().hasName("drive_file_write")
		and target_4.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfile_331
		and target_4.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("void *")
		and target_4.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vLength_332
		and target_4.getParent().(IfStmt).getThen()=target_15
		and target_16.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

*/
predicate func_6(Variable vfile_331, BlockStmt target_17, NotExpr target_6) {
		target_6.getOperand().(VariableAccess).getTarget()=vfile_331
		and target_6.getParent().(IfStmt).getThen()=target_17
}

predicate func_7(Parameter virp_329, FunctionCall target_7) {
		target_7.getTarget().hasName("Stream_Pointer")
		and target_7.getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_7.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_329
}

predicate func_8(Parameter virp_329, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="IoStatus"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_329
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("drive_map_windows_err")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("GetLastError")
}

predicate func_9(Variable vLength_332, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vLength_332
		and target_9.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_10(Variable vfile_331, Variable vLength_332, NotExpr target_10) {
		target_10.getOperand().(FunctionCall).getTarget().hasName("drive_file_write")
		and target_10.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfile_331
		and target_10.getOperand().(FunctionCall).getArgument(1) instanceof FunctionCall
		and target_10.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vLength_332
}

predicate func_11(Parameter virp_329, Variable vfile_331, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfile_331
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("drive_get_file_by_id")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="FileId"
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_329
}

predicate func_12(Variable vLength_332, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vLength_332
		and target_12.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_12.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_12.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="16"
		and target_12.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_12.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="3"
		and target_12.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="24"
}

predicate func_13(Parameter virp_329, Variable vLength_332, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("Stream_Write_UINT32")
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="output"
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_329
		and target_13.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vLength_332
}

predicate func_14(Variable vOffset_333, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vOffset_333
		and target_14.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="40"
		and target_14.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="48"
		and target_14.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_14.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="7"
		and target_14.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="56"
}

predicate func_15(Parameter virp_329, Variable vLength_332, BlockStmt target_15) {
		target_15.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="IoStatus"
		and target_15.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_329
		and target_15.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("drive_map_windows_err")
		and target_15.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("GetLastError")
		and target_15.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vLength_332
		and target_15.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_16(Variable vfile_331, Variable vOffset_333, NotExpr target_16) {
		target_16.getOperand().(FunctionCall).getTarget().hasName("drive_file_seek")
		and target_16.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfile_331
		and target_16.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vOffset_333
}

predicate func_17(Parameter virp_329, Variable vLength_332, BlockStmt target_17) {
		target_17.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="IoStatus"
		and target_17.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_329
		and target_17.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="3221225473"
		and target_17.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vLength_332
		and target_17.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Parameter virp_329, Variable vfile_331, Variable vLength_332, Variable vOffset_333, NotExpr target_6, FunctionCall target_7, ExprStmt target_8, ExprStmt target_9, NotExpr target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, ExprStmt target_14, BlockStmt target_15, NotExpr target_16, BlockStmt target_17
where
not func_0(func)
and not func_1(virp_329, vLength_332, target_8, target_7, target_9, target_10)
and not func_2(target_6, func)
and not func_3(virp_329, vfile_331, vLength_332, vOffset_333, target_11, target_6, target_12, target_13, target_14, func)
and func_6(vfile_331, target_17, target_6)
and func_7(virp_329, target_7)
and func_8(virp_329, target_8)
and func_9(vLength_332, target_9)
and func_10(vfile_331, vLength_332, target_10)
and func_11(virp_329, vfile_331, target_11)
and func_12(vLength_332, target_12)
and func_13(virp_329, vLength_332, target_13)
and func_14(vOffset_333, target_14)
and func_15(virp_329, vLength_332, target_15)
and func_16(vfile_331, vOffset_333, target_16)
and func_17(virp_329, vLength_332, target_17)
and virp_329.getType().hasName("IRP *")
and vfile_331.getType().hasName("DRIVE_FILE *")
and vLength_332.getType().hasName("UINT32")
and vOffset_333.getType().hasName("UINT64")
and virp_329.getParentScope+() = func
and vfile_331.getParentScope+() = func
and vLength_332.getParentScope+() = func
and vOffset_333.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
