/**
 * @name libtiff-21d39de1002a5e69caa0574b2cc05d795d6fbfad-writeBufferToSeparateTiles
 * @id cpp/libtiff/21d39de1002a5e69caa0574b2cc05d795d6fbfad/writeBufferToSeparateTiles
 * @description libtiff-21d39de1002a5e69caa0574b2cc05d795d6fbfad-tools/tiffcrop.c-writeBufferToSeparateTiles CVE-2016-9532
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vout_1300, Parameter vimagewidth_1301, Parameter vspp_1301, Variable vbps_1308, ExprStmt target_1, RelationalOperation target_2, ExprStmt target_3, AddressOfExpr target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vimagewidth_1301
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vbps_1308
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vspp_1301
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(Literal).getValue()="4294967295"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vimagewidth_1301
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vbps_1308
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vspp_1301
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vimagewidth_1301
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294967288"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("TIFFFileName")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vout_1300
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Error, uint32 overflow when computing (imagewidth * bps * spp) + 7"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vout_1300, Variable vbps_1308, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("TIFFGetField")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vout_1300
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="258"
		and target_1.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbps_1308
}

predicate func_2(Parameter vout_1300, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(FunctionCall).getTarget().hasName("TIFFWriteTile")
		and target_2.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vout_1300
		and target_2.getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("tdata_t")
		and target_2.getLesserOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("uint32")
		and target_2.getLesserOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("uint32")
		and target_2.getLesserOperand().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_2.getLesserOperand().(FunctionCall).getArgument(5).(VariableAccess).getTarget().getType().hasName("tsample_t")
		and target_2.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_3(Parameter vimagewidth_1301, Parameter vspp_1301, Variable vbps_1308, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_3.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vimagewidth_1301
		and target_3.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vspp_1301
		and target_3.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vbps_1308
		and target_3.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="7"
		and target_3.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(Literal).getValue()="8"
}

predicate func_4(Variable vbps_1308, AddressOfExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vbps_1308
}

from Function func, Parameter vout_1300, Parameter vimagewidth_1301, Parameter vspp_1301, Variable vbps_1308, ExprStmt target_1, RelationalOperation target_2, ExprStmt target_3, AddressOfExpr target_4
where
not func_0(vout_1300, vimagewidth_1301, vspp_1301, vbps_1308, target_1, target_2, target_3, target_4, func)
and func_1(vout_1300, vbps_1308, target_1)
and func_2(vout_1300, target_2)
and func_3(vimagewidth_1301, vspp_1301, vbps_1308, target_3)
and func_4(vbps_1308, target_4)
and vout_1300.getType().hasName("TIFF *")
and vimagewidth_1301.getType().hasName("uint32")
and vspp_1301.getType().hasName("tsample_t")
and vbps_1308.getType().hasName("uint16")
and vout_1300.getFunction() = func
and vimagewidth_1301.getFunction() = func
and vspp_1301.getFunction() = func
and vbps_1308.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()