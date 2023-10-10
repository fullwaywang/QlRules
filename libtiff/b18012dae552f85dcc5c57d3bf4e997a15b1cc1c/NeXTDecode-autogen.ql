/**
 * @name libtiff-b18012dae552f85dcc5c57d3bf4e997a15b1cc1c-NeXTDecode
 * @id cpp/libtiff/b18012dae552f85dcc5c57d3bf4e997a15b1cc1c/NeXTDecode
 * @description libtiff-b18012dae552f85dcc5c57d3bf4e997a15b1cc1c-libtiff/tif_next.c-NeXTDecode CVE-2015-8784
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vscanline_55, LogicalOrExpr target_4) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof LogicalAndExpr
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("tmsize_t")
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vscanline_55
		and target_4.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(BitwiseAndExpr target_5, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("tmsize_t")
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_5
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vtif_49, Variable vmodule_51, Variable vscanline_55, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("tmsize_t")
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vscanline_55
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_49
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_51
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Invalid data for scanline %ld"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="tif_row"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_49
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_6.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_9.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_3(Variable vn_55, Variable vnpixels_105, Variable vimagewidth_106, LogicalAndExpr target_3) {
		target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vn_55
		and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnpixels_105
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vimagewidth_106
}

predicate func_4(Variable vscanline_55, Variable vn_55, LogicalOrExpr target_4) {
		target_4.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="4"
		and target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vn_55
		and target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vn_55
		and target_4.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vscanline_55
}

predicate func_5(Variable vnpixels_105, BitwiseAndExpr target_5) {
		target_5.getLeftOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vnpixels_105
		and target_5.getRightOperand().(Literal).getValue()="3"
}

predicate func_6(Parameter vtif_49, Variable vimagewidth_106, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vimagewidth_106
		and target_6.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="td_tilewidth"
		and target_6.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_6.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_49
}

predicate func_7(Parameter vtif_49, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tif_rawcp"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_49
		and target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("unsigned char *")
}

predicate func_8(Parameter vtif_49, Variable vmodule_51, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_49
		and target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_51
		and target_8.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Fractional scanlines cannot be read"
}

predicate func_9(Parameter vtif_49, Variable vmodule_51, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_49
		and target_9.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_51
		and target_9.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Not enough data for scanline %ld"
		and target_9.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="tif_row"
		and target_9.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_49
}

from Function func, Parameter vtif_49, Variable vmodule_51, Variable vscanline_55, Variable vn_55, Variable vnpixels_105, Variable vimagewidth_106, LogicalAndExpr target_3, LogicalOrExpr target_4, BitwiseAndExpr target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9
where
not func_0(vscanline_55, target_4)
and not func_1(target_5, func)
and not func_2(vtif_49, vmodule_51, vscanline_55, target_6, target_7, target_8, target_9)
and func_3(vn_55, vnpixels_105, vimagewidth_106, target_3)
and func_4(vscanline_55, vn_55, target_4)
and func_5(vnpixels_105, target_5)
and func_6(vtif_49, vimagewidth_106, target_6)
and func_7(vtif_49, target_7)
and func_8(vtif_49, vmodule_51, target_8)
and func_9(vtif_49, vmodule_51, target_9)
and vtif_49.getType().hasName("TIFF *")
and vmodule_51.getType().hasName("const char[]")
and vscanline_55.getType().hasName("tmsize_t")
and vn_55.getType().hasName("tmsize_t")
and vnpixels_105.getType().hasName("uint32")
and vimagewidth_106.getType().hasName("uint32")
and vtif_49.getFunction() = func
and vmodule_51.(LocalVariable).getFunction() = func
and vscanline_55.(LocalVariable).getFunction() = func
and vn_55.(LocalVariable).getFunction() = func
and vnpixels_105.(LocalVariable).getFunction() = func
and vimagewidth_106.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
