/**
 * @name libtiff-21d39de1002a5e69caa0574b2cc05d795d6fbfad-writeBufferToSeparateStrips
 * @id cpp/libtiff/21d39de1002a5e69caa0574b2cc05d795d6fbfad/writeBufferToSeparateStrips
 * @description libtiff-21d39de1002a5e69caa0574b2cc05d795d6fbfad-tools/tiffcrop.c-writeBufferToSeparateStrips CVE-2016-9532
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vout_1149, Parameter vwidth_1150, Parameter vspp_1150, Variable vbps_1154, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vwidth_1150
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vbps_1154
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vspp_1150
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(Literal).getValue()="4294967295"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vwidth_1150
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vbps_1154
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vspp_1150
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vwidth_1150
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294967288"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("TIFFFileName")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vout_1149
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Error, uint32 overflow when computing (bps * spp * width) + 7"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_0)
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vout_1149, Parameter vwidth_1150, Variable vrowsperstrip_1155, Variable vbytes_per_sample_1156, ExprStmt target_5, ExprStmt target_3, ExprStmt target_6, AddressOfExpr target_7, ExprStmt target_4, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbytes_per_sample_1156
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vrowsperstrip_1155
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(Literal).getValue()="4294967295"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vbytes_per_sample_1156
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vrowsperstrip_1155
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vbytes_per_sample_1156
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(Literal).getValue()="4294967295"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vwidth_1150
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("TIFFFileName")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vout_1149
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Error, uint32 overflow when computing rowsperstrip * bytes_per_sample * (width + 1)"
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_1)
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_7.getOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vout_1149, Variable vbps_1154, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("TIFFGetField")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vout_1149
		and target_2.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="258"
		and target_2.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbps_1154
}

predicate func_3(Parameter vwidth_1150, Parameter vspp_1150, Variable vbps_1154, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_3.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vbps_1154
		and target_3.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vspp_1150
		and target_3.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vwidth_1150
		and target_3.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="7"
		and target_3.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(Literal).getValue()="8"
}

predicate func_4(Variable vbps_1154, Variable vbytes_per_sample_1156, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytes_per_sample_1156
		and target_4.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vbps_1154
		and target_4.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="7"
		and target_4.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(Literal).getValue()="8"
}

predicate func_5(Parameter vout_1149, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("tsize_t")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TIFFVStripSize")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vout_1149
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("uint32")
}

predicate func_6(Parameter vwidth_1150, Variable vrowsperstrip_1155, Variable vbytes_per_sample_1156, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("tsize_t")
		and target_6.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vrowsperstrip_1155
		and target_6.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vbytes_per_sample_1156
		and target_6.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vwidth_1150
		and target_6.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_7(Variable vrowsperstrip_1155, AddressOfExpr target_7) {
		target_7.getOperand().(VariableAccess).getTarget()=vrowsperstrip_1155
}

from Function func, Parameter vout_1149, Parameter vwidth_1150, Parameter vspp_1150, Variable vbps_1154, Variable vrowsperstrip_1155, Variable vbytes_per_sample_1156, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, AddressOfExpr target_7
where
not func_0(vout_1149, vwidth_1150, vspp_1150, vbps_1154, target_2, target_3, target_4, func)
and not func_1(vout_1149, vwidth_1150, vrowsperstrip_1155, vbytes_per_sample_1156, target_5, target_3, target_6, target_7, target_4, func)
and func_2(vout_1149, vbps_1154, target_2)
and func_3(vwidth_1150, vspp_1150, vbps_1154, target_3)
and func_4(vbps_1154, vbytes_per_sample_1156, target_4)
and func_5(vout_1149, target_5)
and func_6(vwidth_1150, vrowsperstrip_1155, vbytes_per_sample_1156, target_6)
and func_7(vrowsperstrip_1155, target_7)
and vout_1149.getType().hasName("TIFF *")
and vwidth_1150.getType().hasName("uint32")
and vspp_1150.getType().hasName("uint16")
and vbps_1154.getType().hasName("uint16")
and vrowsperstrip_1155.getType().hasName("uint32")
and vbytes_per_sample_1156.getType().hasName("uint32")
and vout_1149.getFunction() = func
and vwidth_1150.getFunction() = func
and vspp_1150.getFunction() = func
and vbps_1154.(LocalVariable).getFunction() = func
and vrowsperstrip_1155.(LocalVariable).getFunction() = func
and vbytes_per_sample_1156.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
