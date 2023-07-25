/**
 * @name libtiff-cfbb883bf6ea7bedcb04177cc4e52d304522fdff-writeBufferToSeparateTiles
 * @id cpp/libtiff/cfbb883bf6ea7bedcb04177cc4e52d304522fdff/writeBufferToSeparateTiles
 * @description libtiff-cfbb883bf6ea7bedcb04177cc4e52d304522fdff-tools/tiffcrop.c-writeBufferToSeparateTiles CVE-2022-3598
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(AddExpr target_0 |
		target_0.getAnOperand() instanceof FunctionCall
		and target_0.getAnOperand().(Literal).getValue()="3"
		and target_0.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getTarget().hasName("limitMalloc")
		and target_0.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(0) instanceof FunctionCall
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vobuf_1361, Parameter vout_1357, EqualityOperation target_3, ExprStmt target_4, FunctionCall target_2, LogicalOrExpr target_5, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vobuf_1361
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("TIFFTileSize")
		and target_1.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vout_1357
		and target_1.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="3"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_1)
		and target_3.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vout_1357, FunctionCall target_2) {
		target_2.getTarget().hasName("TIFFTileSize")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vout_1357
		and target_2.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getTarget().hasName("limitMalloc")
}

predicate func_3(Variable vobuf_1361, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vobuf_1361
		and target_3.getAnOperand().(Literal).getValue()="0"
}

predicate func_4(Variable vobuf_1361, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("_TIFFfree")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vobuf_1361
}

predicate func_5(Parameter vout_1357, LogicalOrExpr target_5) {
		target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("TIFFGetField")
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vout_1357
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="323"
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("TIFFGetField")
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vout_1357
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="322"
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("TIFFGetField")
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vout_1357
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="258"
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("uint16_t")
}

from Function func, Variable vobuf_1361, Parameter vout_1357, FunctionCall target_2, EqualityOperation target_3, ExprStmt target_4, LogicalOrExpr target_5
where
not func_0(func)
and not func_1(vobuf_1361, vout_1357, target_3, target_4, target_2, target_5, func)
and func_2(vout_1357, target_2)
and func_3(vobuf_1361, target_3)
and func_4(vobuf_1361, target_4)
and func_5(vout_1357, target_5)
and vobuf_1361.getType().hasName("tdata_t")
and vout_1357.getType().hasName("TIFF *")
and vobuf_1361.(LocalVariable).getFunction() = func
and vout_1357.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
