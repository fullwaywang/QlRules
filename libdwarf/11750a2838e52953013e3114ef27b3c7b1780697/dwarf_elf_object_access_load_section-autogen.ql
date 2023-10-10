/**
 * @name libdwarf-11750a2838e52953013e3114ef27b3c7b1780697-dwarf_elf_object_access_load_section
 * @id cpp/libdwarf/11750a2838e52953013e3114ef27b3c7b1780697/dwarf-elf-object-access-load-section
 * @description libdwarf-11750a2838e52953013e3114ef27b3c7b1780697-libdwarf/dwarf_elf_access.c-dwarf_elf_object_access_load_section CVE-2015-8750
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter verror_1209, Variable vdata_1219, ExprStmt target_1, EqualityOperation target_2, ExprStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="d_buf"
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1219
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=verror_1209
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="10"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="1"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_2.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter verror_1209, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=verror_1209
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="10"
}

predicate func_2(Variable vdata_1219, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vdata_1219
		and target_2.getAnOperand().(Literal).getValue()="0"
}

predicate func_3(Variable vdata_1219, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("Dwarf_Small **")
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="d_buf"
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1219
}

from Function func, Parameter verror_1209, Variable vdata_1219, ExprStmt target_1, EqualityOperation target_2, ExprStmt target_3
where
not func_0(verror_1209, vdata_1219, target_1, target_2, target_3)
and func_1(verror_1209, target_1)
and func_2(vdata_1219, target_2)
and func_3(vdata_1219, target_3)
and verror_1209.getType().hasName("int *")
and vdata_1219.getType().hasName("Elf_Data *")
and verror_1209.getFunction() = func
and vdata_1219.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
