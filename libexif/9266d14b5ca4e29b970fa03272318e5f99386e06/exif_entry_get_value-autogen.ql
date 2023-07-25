/**
 * @name libexif-9266d14b5ca4e29b970fa03272318e5f99386e06-exif_entry_get_value
 * @id cpp/libexif/9266d14b5ca4e29b970fa03272318e5f99386e06/exif-entry-get-value
 * @description libexif-9266d14b5ca4e29b970fa03272318e5f99386e06-libexif/exif-entry.c-exif_entry_get_value CVE-2020-0452
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="1"
		and not target_0.getValue()="65536"
		and target_0.getParent().(AddExpr).getParent().(LTExpr).getLesserOperand() instanceof AddExpr
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter ve_834, BreakStmt target_5, RelationalOperation target_4, PointerFieldAccess target_6) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_1.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ve_834
		and target_1.getLesserOperand().(SubExpr).getValue()="65532"
		and target_1.getParent().(IfStmt).getThen()=target_5
		and target_4.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter ve_834, AddExpr target_2) {
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ve_834
		and target_2.getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_2.getAnOperand().(SizeofTypeOperator).getValue()="2"
}

predicate func_3(Parameter ve_834, BreakStmt target_5, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="size"
		and target_3.getQualifier().(VariableAccess).getTarget()=ve_834
		and target_3.getParent().(LTExpr).getLesserOperand() instanceof AddExpr
		and target_3.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_5
}

predicate func_4(Parameter ve_834, BreakStmt target_5, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(AddExpr).getAnOperand() instanceof AddExpr
		and target_4.getLesserOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_4.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_4.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ve_834
		and target_4.getParent().(IfStmt).getThen()=target_5
}

predicate func_5(BreakStmt target_5) {
		target_5.toString() = "break;"
}

predicate func_6(Parameter ve_834, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="mem"
		and target_6.getQualifier().(PointerFieldAccess).getTarget().getName()="priv"
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ve_834
}

from Function func, Parameter ve_834, Literal target_0, AddExpr target_2, PointerFieldAccess target_3, RelationalOperation target_4, BreakStmt target_5, PointerFieldAccess target_6
where
func_0(func, target_0)
and not func_1(ve_834, target_5, target_4, target_6)
and func_2(ve_834, target_2)
and func_3(ve_834, target_5, target_3)
and func_4(ve_834, target_5, target_4)
and func_5(target_5)
and func_6(ve_834, target_6)
and ve_834.getType().hasName("ExifEntry *")
and ve_834.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
