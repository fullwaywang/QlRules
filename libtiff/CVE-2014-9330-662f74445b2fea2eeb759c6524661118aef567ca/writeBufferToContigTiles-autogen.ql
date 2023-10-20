/**
 * @name libtiff-662f74445b2fea2eeb759c6524661118aef567ca-writeBufferToContigTiles
 * @id cpp/libtiff/662f74445b2fea2eeb759c6524661118aef567ca/writeBufferToContigTiles
 * @description libtiff-662f74445b2fea2eeb759c6524661118aef567ca-tools/tiffcrop.c-writeBufferToContigTiles CVE-2014-9330
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand() instanceof FunctionCall
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand() instanceof FunctionCall
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand() instanceof FunctionCall
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0))
}

predicate func_1(Variable vtl_1199, Parameter vout_1194, FunctionCall target_1) {
		target_1.getTarget().hasName("TIFFGetField")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vout_1194
		and target_1.getArgument(1).(Literal).getValue()="323"
		and target_1.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vtl_1199
}

predicate func_2(Variable vtw_1199, Parameter vout_1194, FunctionCall target_2) {
		target_2.getTarget().hasName("TIFFGetField")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vout_1194
		and target_2.getArgument(1).(Literal).getValue()="322"
		and target_2.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vtw_1199
}

predicate func_3(Variable vbps_1198, Parameter vout_1194, FunctionCall target_3) {
		target_3.getTarget().hasName("TIFFGetField")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vout_1194
		and target_3.getArgument(1).(Literal).getValue()="258"
		and target_3.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbps_1198
}

predicate func_4(Function func, ExprStmt target_4) {
		target_4.getExpr() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Function func, ExprStmt target_5) {
		target_5.getExpr() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

predicate func_6(Function func, ExprStmt target_6) {
		target_6.getExpr() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

from Function func, Variable vbps_1198, Variable vtl_1199, Variable vtw_1199, Parameter vout_1194, FunctionCall target_1, FunctionCall target_2, FunctionCall target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6
where
not func_0(func)
and func_1(vtl_1199, vout_1194, target_1)
and func_2(vtw_1199, vout_1194, target_2)
and func_3(vbps_1198, vout_1194, target_3)
and func_4(func, target_4)
and func_5(func, target_5)
and func_6(func, target_6)
and vbps_1198.getType().hasName("uint16")
and vtl_1199.getType().hasName("uint32")
and vtw_1199.getType().hasName("uint32")
and vout_1194.getType().hasName("TIFF *")
and vbps_1198.(LocalVariable).getFunction() = func
and vtl_1199.(LocalVariable).getFunction() = func
and vtw_1199.(LocalVariable).getFunction() = func
and vout_1194.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
