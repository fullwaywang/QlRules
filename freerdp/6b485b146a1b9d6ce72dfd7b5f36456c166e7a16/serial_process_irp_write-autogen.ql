/**
 * @name freerdp-6b485b146a1b9d6ce72dfd7b5f36456c166e7a16-serial_process_irp_write
 * @id cpp/freerdp/6b485b146a1b9d6ce72dfd7b5f36456c166e7a16/serial-process-irp-write
 * @description freerdp-6b485b146a1b9d6ce72dfd7b5f36456c166e7a16-channels/serial/client/serial_main.c-serial_process_irp_write CVE-2020-11089
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter virp_299, BlockStmt target_10, ExprStmt target_11, FunctionCall target_7) {
	exists(NotExpr target_0 |
		target_0.getOperand().(FunctionCall).getTarget().hasName("Stream_SafeSeek")
		and target_0.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_0.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_299
		and target_0.getOperand().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getParent().(IfStmt).getThen()=target_10
		and target_11.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(FunctionCall target_12, Function func) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(Literal).getValue()="13"
		and target_1.getParent().(IfStmt).getCondition()=target_12
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getType().hasName("void *")
		and target_2.getRValue() instanceof FunctionCall
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter virp_299, Variable vLength_301, ExprStmt target_13, ExprStmt target_14, FunctionCall target_12, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Stream_SafeSeek")
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_299
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vLength_301
		and target_3.getThen().(ReturnStmt).getExpr().(Literal).getValue()="13"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_3)
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_12.getArgument(2).(VariableAccess).getLocation().isBefore(target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_4(Parameter virp_299, Variable vLength_301, Variable vnbWritten_303, Parameter vserial_299, FunctionCall target_7, ExprStmt target_15, ExprStmt target_16, ValueFieldAccess target_17, FunctionCall target_18, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(FunctionCall).getTarget().hasName("CommWriteFile")
		and target_4.getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="hComm"
		and target_4.getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vserial_299
		and target_4.getCondition().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("void *")
		and target_4.getCondition().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vLength_301
		and target_4.getCondition().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vnbWritten_303
		and target_4.getCondition().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="IoStatus"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_299
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getElse().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_4.getElse().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("WLog_IsLevelActive")
		and target_4.getElse().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_4.getElse().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof Literal
		and target_4.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="IoStatus"
		and target_4.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_299
		and target_4.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_GetLastErrorToIoStatus")
		and target_4.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vserial_299
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_4)
		and target_7.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_15.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getLocation().isBefore(target_4.getCondition().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_4.getCondition().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_16.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getLocation())
		and target_17.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_18.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(Parameter virp_299, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="input"
		and target_6.getQualifier().(VariableAccess).getTarget()=virp_299
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_7(Parameter virp_299, FunctionCall target_7) {
		target_7.getTarget().hasName("Stream_Pointer")
		and target_7.getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_7.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_299
}

predicate func_9(Parameter virp_299, FunctionCall target_9) {
		target_9.getTarget().hasName("Stream_Seek")
		and target_9.getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_9.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_299
		and target_9.getArgument(1) instanceof Literal
}

predicate func_10(Parameter virp_299, BlockStmt target_10) {
		target_10.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="IoStatus"
		and target_10.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_299
		and target_10.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_11(Parameter virp_299, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_11.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_11.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_299
		and target_11.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_11.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="8"
}

predicate func_12(Variable vLength_301, Variable vnbWritten_303, Parameter vserial_299, FunctionCall target_12) {
		target_12.getTarget().hasName("CommWriteFile")
		and target_12.getArgument(0).(PointerFieldAccess).getTarget().getName()="hComm"
		and target_12.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vserial_299
		and target_12.getArgument(1) instanceof FunctionCall
		and target_12.getArgument(2).(VariableAccess).getTarget()=vLength_301
		and target_12.getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vnbWritten_303
		and target_12.getArgument(4).(Literal).getValue()="0"
}

predicate func_13(Parameter virp_299, Parameter vserial_299, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="IoStatus"
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_299
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_GetLastErrorToIoStatus")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vserial_299
}

predicate func_14(Parameter virp_299, Variable vnbWritten_303, ExprStmt target_14) {
		target_14.getExpr().(FunctionCall).getTarget().hasName("Stream_Write_UINT32")
		and target_14.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="output"
		and target_14.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_299
		and target_14.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnbWritten_303
}

predicate func_15(Variable vLength_301, Parameter vserial_299, ExprStmt target_15) {
		target_15.getExpr().(FunctionCall).getTarget().hasName("WLog_PrintMessage")
		and target_15.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_15.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vserial_299
		and target_15.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_15.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_15.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_15.getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_15.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="writing %u bytes to %s"
		and target_15.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vLength_301
		and target_15.getExpr().(FunctionCall).getArgument(8).(ValueFieldAccess).getTarget().getName()="name"
		and target_15.getExpr().(FunctionCall).getArgument(8).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="device"
		and target_15.getExpr().(FunctionCall).getArgument(8).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vserial_299
}

predicate func_16(Variable vnbWritten_303, Parameter vserial_299, ExprStmt target_16) {
		target_16.getExpr().(FunctionCall).getTarget().hasName("WLog_PrintMessage")
		and target_16.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_16.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vserial_299
		and target_16.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_16.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_16.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_16.getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_16.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="write failure to %s, nbWritten=%u, last-error: 0x%08X"
		and target_16.getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getTarget().getName()="name"
		and target_16.getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="device"
		and target_16.getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vserial_299
		and target_16.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vnbWritten_303
		and target_16.getExpr().(FunctionCall).getArgument(9).(FunctionCall).getTarget().hasName("GetLastError")
}

predicate func_17(Parameter vserial_299, ValueFieldAccess target_17) {
		target_17.getTarget().getName()="name"
		and target_17.getQualifier().(PointerFieldAccess).getTarget().getName()="device"
		and target_17.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vserial_299
}

predicate func_18(Parameter vserial_299, FunctionCall target_18) {
		target_18.getTarget().hasName("WLog_IsLevelActive")
		and target_18.getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_18.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vserial_299
		and target_18.getArgument(1) instanceof Literal
}

from Function func, Parameter virp_299, Variable vLength_301, Variable vnbWritten_303, Parameter vserial_299, PointerFieldAccess target_6, FunctionCall target_7, FunctionCall target_9, BlockStmt target_10, ExprStmt target_11, FunctionCall target_12, ExprStmt target_13, ExprStmt target_14, ExprStmt target_15, ExprStmt target_16, ValueFieldAccess target_17, FunctionCall target_18
where
not func_0(virp_299, target_10, target_11, target_7)
and not func_1(target_12, func)
and not func_2(func)
and not func_3(virp_299, vLength_301, target_13, target_14, target_12, func)
and not func_4(virp_299, vLength_301, vnbWritten_303, vserial_299, target_7, target_15, target_16, target_17, target_18, func)
and func_6(virp_299, target_6)
and func_7(virp_299, target_7)
and func_9(virp_299, target_9)
and func_10(virp_299, target_10)
and func_11(virp_299, target_11)
and func_12(vLength_301, vnbWritten_303, vserial_299, target_12)
and func_13(virp_299, vserial_299, target_13)
and func_14(virp_299, vnbWritten_303, target_14)
and func_15(vLength_301, vserial_299, target_15)
and func_16(vnbWritten_303, vserial_299, target_16)
and func_17(vserial_299, target_17)
and func_18(vserial_299, target_18)
and virp_299.getType().hasName("IRP *")
and vLength_301.getType().hasName("UINT32")
and vnbWritten_303.getType().hasName("DWORD")
and vserial_299.getType().hasName("SERIAL_DEVICE *")
and virp_299.getParentScope+() = func
and vLength_301.getParentScope+() = func
and vnbWritten_303.getParentScope+() = func
and vserial_299.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
