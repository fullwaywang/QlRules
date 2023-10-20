/**
 * @name ghostscript-2793769ff107d8d22dadd30c6e68cd781b569550-pcx_write_rle
 * @id cpp/ghostscript/2793769ff107d8d22dadd30c6e68cd781b569550/pcx-write-rle
 * @description ghostscript-2793769ff107d8d22dadd30c6e68cd781b569550-devices/gdevpcx.c-pcx_write_rle CVE-2020-16305
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vfrom_432, Parameter vend_432, BlockStmt target_4, LogicalOrExpr target_5, RelationalOperation target_6, LogicalAndExpr target_7) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=vfrom_432
		and target_0.getLesserOperand().(VariableAccess).getTarget()=vend_432
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("byte")
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vfrom_432
		and target_0.getParent().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_4
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getGreaterOperand().(VariableAccess).getLocation())
		and target_6.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getLesserOperand().(VariableAccess).getLocation())
		and target_0.getLesserOperand().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vfrom_432, VariableAccess target_1) {
		target_1.getTarget()=vfrom_432
}

predicate func_2(Parameter vend_432, VariableAccess target_2) {
		target_2.getTarget()=vend_432
}

predicate func_3(Parameter vfrom_432, Parameter vend_432, BlockStmt target_4, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vfrom_432
		and target_3.getAnOperand().(VariableAccess).getTarget()=vend_432
		and target_3.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_4
}

predicate func_4(BlockStmt target_4) {
		target_4.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget().getType().hasName("byte")
		and target_4.getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(HexLiteral).getValue()="192"
		and target_4.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("gp_fputc")
		and target_4.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(HexLiteral).getValue()="193"
		and target_4.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("gp_file *")
}

predicate func_5(Parameter vfrom_432, LogicalOrExpr target_5) {
		target_5.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("byte")
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vfrom_432
		and target_5.getAnOperand() instanceof EqualityOperation
}

predicate func_6(Parameter vfrom_432, Parameter vend_432, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getLesserOperand().(VariableAccess).getTarget()=vfrom_432
		and target_6.getGreaterOperand().(VariableAccess).getTarget()=vend_432
}

predicate func_7(Parameter vfrom_432, Parameter vend_432, LogicalAndExpr target_7) {
		target_7.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vfrom_432
		and target_7.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vend_432
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vfrom_432
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("byte")
}

from Function func, Parameter vfrom_432, Parameter vend_432, VariableAccess target_1, VariableAccess target_2, EqualityOperation target_3, BlockStmt target_4, LogicalOrExpr target_5, RelationalOperation target_6, LogicalAndExpr target_7
where
not func_0(vfrom_432, vend_432, target_4, target_5, target_6, target_7)
and func_1(vfrom_432, target_1)
and func_2(vend_432, target_2)
and func_3(vfrom_432, vend_432, target_4, target_3)
and func_4(target_4)
and func_5(vfrom_432, target_5)
and func_6(vfrom_432, vend_432, target_6)
and func_7(vfrom_432, vend_432, target_7)
and vfrom_432.getType().hasName("const byte *")
and vend_432.getType().hasName("const byte *")
and vfrom_432.getFunction() = func
and vend_432.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
