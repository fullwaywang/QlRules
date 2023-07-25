/**
 * @name libtiff-e813112545942107551433d61afd16ac094ff246-TIFFPrintDirectory
 * @id cpp/libtiff/e813112545942107551433d61afd16ac094ff246/TIFFPrintDirectory
 * @description libtiff-e813112545942107551433d61afd16ac094ff246-libtiff/tif_print.c-TIFFPrintDirectory CVE-2022-3599
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vfd_235, Variable vtd_237, Parameter vtif_235, ExprStmt target_1, ExprStmt target_2, SubExpr target_3, SwitchStmt target_4, BitwiseAndExpr target_5, BitwiseAndExpr target_6, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="td_fieldsset"
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_235
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(DivExpr).getValue()="1"
		and target_0.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="262144"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfd_235
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="  NumberOfInks: %d\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="td_numberofinks"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_237
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vfd_235, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("fputs")
		and target_1.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="\n"
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfd_235
}

predicate func_2(Parameter vfd_235, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfd_235
		and target_2.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="  Thresholding: "
}

predicate func_3(Variable vtd_237, SubExpr target_3) {
		target_3.getLeftOperand().(PointerFieldAccess).getTarget().getName()="td_inknameslen"
		and target_3.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_237
		and target_3.getRightOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget().getType().hasName("char *")
		and target_3.getRightOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="td_inknames"
		and target_3.getRightOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_237
}

predicate func_4(Parameter vfd_235, Variable vtd_237, SwitchStmt target_4) {
		target_4.getExpr().(PointerFieldAccess).getTarget().getName()="td_threshholding"
		and target_4.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_237
		and target_4.getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(Literal).getValue()="1"
		and target_4.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_4.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfd_235
		and target_4.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="bilevel art scan\n"
		and target_4.getStmt().(BlockStmt).getStmt(3).(SwitchCase).getExpr().(Literal).getValue()="2"
}

predicate func_5(Parameter vtif_235, BitwiseAndExpr target_5) {
		target_5.getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="td_fieldsset"
		and target_5.getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_5.getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_235
		and target_5.getLeftOperand().(ArrayExpr).getArrayOffset().(DivExpr).getValue()="1"
		and target_5.getRightOperand().(BinaryBitwiseOperation).getValue()="16384"
}

predicate func_6(Parameter vtif_235, BitwiseAndExpr target_6) {
		target_6.getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="td_fieldsset"
		and target_6.getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_6.getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_235
		and target_6.getLeftOperand().(ArrayExpr).getArrayOffset().(DivExpr).getValue()="0"
		and target_6.getRightOperand().(BinaryBitwiseOperation).getValue()="512"
}

from Function func, Parameter vfd_235, Variable vtd_237, Parameter vtif_235, ExprStmt target_1, ExprStmt target_2, SubExpr target_3, SwitchStmt target_4, BitwiseAndExpr target_5, BitwiseAndExpr target_6
where
not func_0(vfd_235, vtd_237, vtif_235, target_1, target_2, target_3, target_4, target_5, target_6, func)
and func_1(vfd_235, target_1)
and func_2(vfd_235, target_2)
and func_3(vtd_237, target_3)
and func_4(vfd_235, vtd_237, target_4)
and func_5(vtif_235, target_5)
and func_6(vtif_235, target_6)
and vfd_235.getType().hasName("FILE *")
and vtd_237.getType().hasName("TIFFDirectory *")
and vtif_235.getType().hasName("TIFF *")
and vfd_235.getFunction() = func
and vtd_237.(LocalVariable).getFunction() = func
and vtif_235.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
