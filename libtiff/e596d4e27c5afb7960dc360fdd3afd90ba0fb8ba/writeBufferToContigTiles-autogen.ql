/**
 * @name libtiff-e596d4e27c5afb7960dc360fdd3afd90ba0fb8ba-writeBufferToContigTiles
 * @id cpp/libtiff/e596d4e27c5afb7960dc360fdd3afd90ba0fb8ba/writeBufferToContigTiles
 * @description libtiff-e596d4e27c5afb7960dc360fdd3afd90ba0fb8ba-tools/tiffcrop.c-writeBufferToContigTiles CVE-2016-3991
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtl_1199, Variable vtw_1199, Variable vtile_rowsize_1202, Variable vtilesize_1205, AddressOfExpr target_2, RelationalOperation target_3, AddressOfExpr target_4, AssignAddExpr target_5, ExprStmt target_6, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtilesize_1205
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtile_rowsize_1202
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtl_1199
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtw_1199
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="writeBufferToContigTiles"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Tile size, tile row size, tile width, or tile length is zero"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exit")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0)
		and target_2.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getRValue().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vtl_1199, Variable vtile_rowsize_1202, Variable vtile_buffsize_1204, RelationalOperation target_3, ExprStmt target_7, AssignAddExpr target_8, ExprStmt target_9) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtl_1199
		and target_1.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vtile_buffsize_1204
		and target_1.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vtile_rowsize_1202
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="writeBufferToContigTiles"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Integer overflow when calculating buffer size"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exit")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getValue()="-1"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_7.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_8.getRValue().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vtl_1199, AddressOfExpr target_2) {
		target_2.getOperand().(VariableAccess).getTarget()=vtl_1199
}

predicate func_3(Variable vtl_1199, Variable vtile_rowsize_1202, Variable vtilesize_1205, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vtilesize_1205
		and target_3.getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vtl_1199
		and target_3.getGreaterOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vtile_rowsize_1202
}

predicate func_4(Variable vtw_1199, AddressOfExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vtw_1199
}

predicate func_5(Variable vtw_1199, AssignAddExpr target_5) {
		target_5.getLValue().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_5.getRValue().(VariableAccess).getTarget()=vtw_1199
}

predicate func_6(Variable vtile_buffsize_1204, Variable vtilesize_1205, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtile_buffsize_1204
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vtilesize_1205
}

predicate func_7(Variable vtl_1199, Variable vtile_rowsize_1202, Variable vtile_buffsize_1204, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtile_buffsize_1204
		and target_7.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vtl_1199
		and target_7.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vtile_rowsize_1202
}

predicate func_8(Variable vtl_1199, AssignAddExpr target_8) {
		target_8.getLValue().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_8.getRValue().(VariableAccess).getTarget()=vtl_1199
}

predicate func_9(Variable vtile_buffsize_1204, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFmalloc")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtile_buffsize_1204
}

from Function func, Variable vtl_1199, Variable vtw_1199, Variable vtile_rowsize_1202, Variable vtile_buffsize_1204, Variable vtilesize_1205, AddressOfExpr target_2, RelationalOperation target_3, AddressOfExpr target_4, AssignAddExpr target_5, ExprStmt target_6, ExprStmt target_7, AssignAddExpr target_8, ExprStmt target_9
where
not func_0(vtl_1199, vtw_1199, vtile_rowsize_1202, vtilesize_1205, target_2, target_3, target_4, target_5, target_6, func)
and not func_1(vtl_1199, vtile_rowsize_1202, vtile_buffsize_1204, target_3, target_7, target_8, target_9)
and func_2(vtl_1199, target_2)
and func_3(vtl_1199, vtile_rowsize_1202, vtilesize_1205, target_3)
and func_4(vtw_1199, target_4)
and func_5(vtw_1199, target_5)
and func_6(vtile_buffsize_1204, vtilesize_1205, target_6)
and func_7(vtl_1199, vtile_rowsize_1202, vtile_buffsize_1204, target_7)
and func_8(vtl_1199, target_8)
and func_9(vtile_buffsize_1204, target_9)
and vtl_1199.getType().hasName("uint32")
and vtw_1199.getType().hasName("uint32")
and vtile_rowsize_1202.getType().hasName("uint32")
and vtile_buffsize_1204.getType().hasName("tsize_t")
and vtilesize_1205.getType().hasName("tsize_t")
and vtl_1199.(LocalVariable).getFunction() = func
and vtw_1199.(LocalVariable).getFunction() = func
and vtile_rowsize_1202.(LocalVariable).getFunction() = func
and vtile_buffsize_1204.(LocalVariable).getFunction() = func
and vtilesize_1205.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
