/**
 * @name libtiff-6a4dbb07ccf92836bb4adac7be4575672d0ac5f1-PixarLogEncode
 * @id cpp/libtiff/6a4dbb07ccf92836bb4adac7be4575672d0ac5f1/PixarLogEncode
 * @description libtiff-6a4dbb07ccf92836bb4adac7be4575672d0ac5f1-libtiff/tif_pixarlog.c-PixarLogEncode CVE-2016-3990
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmodule_1113, Variable vtd_1114, Variable vn_1117, Variable vllen_1118, Parameter vtif_1111, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, RelationalOperation target_5, CommaExpr target_6, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vn_1117
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="td_rowsperstrip"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_1114
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vllen_1118
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_1111
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_1113
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Too many input bytes provided"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_6.getLeftOperand().(AssignAddExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vmodule_1113, Variable vtd_1114, Parameter vtif_1111, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_1111
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_1113
		and target_1.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%d bit input not supported in PixarLog"
		and target_1.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="td_bitspersample"
		and target_1.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_1114
}

predicate func_2(Variable vmodule_1113, Variable vtd_1114, Parameter vtif_1111, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_1111
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_1113
		and target_2.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%d bit input not supported in PixarLog"
		and target_2.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="td_bitspersample"
		and target_2.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_1114
}

predicate func_3(Variable vtd_1114, Variable vllen_1118, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vllen_1118
		and target_3.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="stride"
		and target_3.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("PixarLogState *")
		and target_3.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="td_imagewidth"
		and target_3.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_1114
}

predicate func_4(Variable vn_1117, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_1117
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("tmsize_t")
}

predicate func_5(Variable vn_1117, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getLesserOperand().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_5.getGreaterOperand().(VariableAccess).getTarget()=vn_1117
}

predicate func_6(Variable vllen_1118, CommaExpr target_6) {
		target_6.getLeftOperand().(AssignAddExpr).getLValue().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_6.getLeftOperand().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vllen_1118
		and target_6.getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget().getType().hasName("unsigned short *")
		and target_6.getRightOperand().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vllen_1118
}

from Function func, Variable vmodule_1113, Variable vtd_1114, Variable vn_1117, Variable vllen_1118, Parameter vtif_1111, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, RelationalOperation target_5, CommaExpr target_6
where
not func_0(vmodule_1113, vtd_1114, vn_1117, vllen_1118, vtif_1111, target_1, target_2, target_3, target_4, target_5, target_6, func)
and func_1(vmodule_1113, vtd_1114, vtif_1111, target_1)
and func_2(vmodule_1113, vtd_1114, vtif_1111, target_2)
and func_3(vtd_1114, vllen_1118, target_3)
and func_4(vn_1117, target_4)
and func_5(vn_1117, target_5)
and func_6(vllen_1118, target_6)
and vmodule_1113.getType().hasName("const char[]")
and vtd_1114.getType().hasName("TIFFDirectory *")
and vn_1117.getType().hasName("tmsize_t")
and vllen_1118.getType().hasName("int")
and vtif_1111.getType().hasName("TIFF *")
and vmodule_1113.(LocalVariable).getFunction() = func
and vtd_1114.(LocalVariable).getFunction() = func
and vn_1117.(LocalVariable).getFunction() = func
and vllen_1118.(LocalVariable).getFunction() = func
and vtif_1111.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
