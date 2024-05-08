/**
 * @name mysql-server-4bf2e863c3e2b59328e591094773722aa928d3a3-fil_tablespace_redo_extend
 * @id cpp/mysql-server/4bf2e863c3e2b59328e591094773722aa928d3a3/filtablespaceredoextend
 * @description mysql-server-4bf2e863c3e2b59328e591094773722aa928d3a3-storage/innobase/fil/fil0fil.cc-fil_tablespace_redo_extend mysql-#32748733
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
	target_0.getValue()="initial_fsize == (file->size * phy_page_size)"
	and not target_0.getValue()="initial_fsize / (phy_page_size * FSP_EXTENT_SIZE) == file->size / FSP_EXTENT_SIZE"
	and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, StringLiteral target_1) {
	target_1.getValue()="(offset % phy_page_size) == 0"
	and not target_1.getValue()="((offset + size) % phy_page_size) == 0"
	and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vphy_page_size_10714, Variable vinitial_fsize_10720, NotExpr target_14, RelationalOperation target_15) {
exists(DivExpr target_2 |
	exists(MulExpr obj_0 | obj_0=target_2.getRightOperand() |
		exists(ConditionalExpr obj_1 | obj_1=obj_0.getRightOperand() |
			exists(RelationalOperation obj_2 | obj_2=obj_1.getCondition() |
				obj_2.getLesserOperand().(VariableAccess).getType().hasName("ulong")
				and obj_2.getGreaterOperand() instanceof Literal
			)
			and exists(DivExpr obj_3 | obj_3=obj_1.getThen() |
				obj_3.getLeftOperand() instanceof Literal
				and obj_3.getRightOperand().(VariableAccess).getType().hasName("ulong")
			)
			and exists(ConditionalExpr obj_4 | obj_4=obj_1.getElse() |
				exists(RelationalOperation obj_5 | obj_5=obj_4.getCondition() |
					obj_5.getLesserOperand().(VariableAccess).getType().hasName("ulong")
					and obj_5.getGreaterOperand() instanceof Literal
				)
				and exists(DivExpr obj_6 | obj_6=obj_4.getThen() |
					obj_6.getLeftOperand() instanceof Literal
					and obj_6.getRightOperand().(VariableAccess).getType().hasName("ulong")
				)
				and exists(DivExpr obj_7 | obj_7=obj_4.getElse() |
					obj_7.getLeftOperand() instanceof Literal
					and obj_7.getRightOperand().(VariableAccess).getType().hasName("ulong")
				)
			)
		)
		and obj_0.getLeftOperand().(VariableAccess).getTarget()=vphy_page_size_10714
	)
	and exists(EQExpr obj_8 | obj_8=target_2.getParent() |
		exists(NotExpr obj_9 | obj_9=obj_8.getParent() |
			exists(FunctionCall obj_10 | obj_10=obj_9.getParent() |
				exists(IfStmt obj_11 | obj_11=obj_10.getParent() |
					exists(FunctionCall obj_12 | obj_12=obj_11.getCondition() |
						obj_12.getTarget().hasName("__builtin_expect")
						and obj_12.getArgument(0).(NotExpr).getOperand().(EqualityOperation).getLeftOperand().(VariableAccess).getTarget()=vinitial_fsize_10720
						and obj_12.getArgument(1) instanceof Literal
					)
				)
			)
		)
	)
	and target_2.getLeftOperand().(VariableAccess).getTarget()=vinitial_fsize_10720
	and target_2.getRightOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_14.getOperand().(EqualityOperation).getLeftOperand().(RemExpr).getRightOperand().(VariableAccess).getLocation())
	and target_2.getLeftOperand().(VariableAccess).getLocation().isBefore(target_15.getGreaterOperand().(VariableAccess).getLocation())
)
}

/*predicate func_3(Function func) {
exists(ConditionalExpr target_3 |
	exists(RelationalOperation obj_0 | obj_0=target_3.getCondition() |
		obj_0.getLesserOperand().(VariableAccess).getType().hasName("ulong")
		and obj_0.getGreaterOperand() instanceof Literal
	)
	and exists(DivExpr obj_1 | obj_1=target_3.getThen() |
		obj_1.getLeftOperand() instanceof Literal
		and obj_1.getRightOperand().(VariableAccess).getType().hasName("ulong")
	)
	and exists(ConditionalExpr obj_2 | obj_2=target_3.getElse() |
		exists(RelationalOperation obj_3 | obj_3=obj_2.getCondition() |
			obj_3.getLesserOperand().(VariableAccess).getType().hasName("ulong")
			and obj_3.getGreaterOperand() instanceof Literal
		)
		and exists(DivExpr obj_4 | obj_4=obj_2.getThen() |
			obj_4.getLeftOperand() instanceof Literal
			and obj_4.getRightOperand().(VariableAccess).getType().hasName("ulong")
		)
		and exists(DivExpr obj_5 | obj_5=obj_2.getElse() |
			obj_5.getLeftOperand() instanceof Literal
			and obj_5.getRightOperand().(VariableAccess).getType().hasName("ulong")
		)
	)
	and exists(MulExpr obj_6 | obj_6=target_3.getParent() |
		exists(EQExpr obj_7 | obj_7=obj_6.getParent() |
			exists(NotExpr obj_8 | obj_8=obj_7.getParent() |
				exists(FunctionCall obj_9 | obj_9=obj_8.getParent() |
					exists(IfStmt obj_10 | obj_10=obj_9.getParent() |
						exists(FunctionCall obj_11 | obj_11=obj_10.getCondition() |
							obj_11.getTarget().hasName("__builtin_expect")
							and obj_11.getArgument(1) instanceof Literal
						)
					)
				)
			)
		)
	)
	and target_3.getEnclosingFunction() = func
)
}

*/
predicate func_4(Variable vfile_10708, Variable vinitial_fsize_10720, FunctionCall target_16) {
exists(DivExpr target_4 |
	exists(PointerFieldAccess obj_0 | obj_0=target_4.getLeftOperand() |
		obj_0.getTarget().getName()="size"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vfile_10708
	)
	and exists(ConditionalExpr obj_1 | obj_1=target_4.getRightOperand() |
		exists(RelationalOperation obj_2 | obj_2=obj_1.getCondition() |
			obj_2.getLesserOperand().(VariableAccess).getType().hasName("ulong")
			and obj_2.getGreaterOperand() instanceof Literal
		)
		and exists(DivExpr obj_3 | obj_3=obj_1.getThen() |
			obj_3.getLeftOperand() instanceof Literal
			and obj_3.getRightOperand().(VariableAccess).getType().hasName("ulong")
		)
		and exists(ConditionalExpr obj_4 | obj_4=obj_1.getElse() |
			exists(RelationalOperation obj_5 | obj_5=obj_4.getCondition() |
				obj_5.getLesserOperand().(VariableAccess).getType().hasName("ulong")
				and obj_5.getGreaterOperand() instanceof Literal
			)
			and exists(DivExpr obj_6 | obj_6=obj_4.getThen() |
				obj_6.getLeftOperand() instanceof Literal
				and obj_6.getRightOperand().(VariableAccess).getType().hasName("ulong")
			)
			and exists(DivExpr obj_7 | obj_7=obj_4.getElse() |
				obj_7.getLeftOperand() instanceof Literal
				and obj_7.getRightOperand().(VariableAccess).getType().hasName("ulong")
			)
		)
	)
	and exists(EQExpr obj_8 | obj_8=target_4.getParent() |
		exists(NotExpr obj_9 | obj_9=obj_8.getParent() |
			exists(FunctionCall obj_10 | obj_10=obj_9.getParent() |
				exists(IfStmt obj_11 | obj_11=obj_10.getParent() |
					exists(FunctionCall obj_12 | obj_12=obj_11.getCondition() |
						obj_12.getTarget().hasName("__builtin_expect")
						and obj_12.getArgument(0).(NotExpr).getOperand().(EqualityOperation).getLeftOperand().(VariableAccess).getTarget()=vinitial_fsize_10720
						and obj_12.getArgument(1) instanceof Literal
					)
				)
			)
		)
	)
	and target_4.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getArgument(0).(VariableAccess).getLocation())
)
}

predicate func_5(Variable voffset_10647, Variable vsize_10652, RelationalOperation target_15, EqualityOperation target_17) {
exists(AddExpr target_5 |
	exists(RemExpr obj_0 | obj_0=target_5.getParent() |
		exists(EQExpr obj_1 | obj_1=obj_0.getParent() |
			exists(NotExpr obj_2 | obj_2=obj_1.getParent() |
				exists(FunctionCall obj_3 | obj_3=obj_2.getParent() |
					exists(IfStmt obj_4 | obj_4=obj_3.getParent() |
						exists(FunctionCall obj_5 | obj_5=obj_4.getCondition() |
							obj_5.getTarget().hasName("__builtin_expect")
							and obj_5.getArgument(1) instanceof Literal
						)
					)
				)
			)
		)
	)
	and target_5.getLeftOperand().(VariableAccess).getTarget()=voffset_10647
	and target_5.getRightOperand().(VariableAccess).getTarget()=vsize_10652
	and target_5.getLeftOperand().(VariableAccess).getLocation().isBefore(target_15.getLesserOperand().(AddExpr).getLeftOperand().(VariableAccess).getLocation())
	and target_17.getLeftOperand().(VariableAccess).getLocation().isBefore(target_5.getRightOperand().(VariableAccess).getLocation())
)
}

predicate func_6(Variable vspace_10698, PointerFieldAccess target_6) {
	target_6.getTarget().getName()="id"
	and target_6.getQualifier().(VariableAccess).getTarget()=vspace_10698
	and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

/*predicate func_8(Variable vfile_10708, PointerFieldAccess target_8) {
	exists(MulExpr obj_0 | obj_0=target_8.getParent() |
		exists(EQExpr obj_1 | obj_1=obj_0.getParent() |
			exists(NotExpr obj_2 | obj_2=obj_1.getParent() |
				exists(FunctionCall obj_3 | obj_3=obj_2.getParent() |
					exists(IfStmt obj_4 | obj_4=obj_3.getParent() |
						exists(FunctionCall obj_5 | obj_5=obj_4.getCondition() |
							obj_5.getTarget().hasName("__builtin_expect")
							and obj_5.getArgument(1) instanceof Literal
						)
					)
				)
			)
		)
	)
	and target_8.getTarget().getName()="size"
	and target_8.getQualifier().(VariableAccess).getTarget()=vfile_10708
}

*/
/*predicate func_9(Variable vinitial_fsize_10720, VariableAccess target_9) {
	exists(EQExpr obj_0 | obj_0=target_9.getParent() |
		exists(NotExpr obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getParent() |
				exists(IfStmt obj_3 | obj_3=obj_2.getParent() |
					exists(FunctionCall obj_4 | obj_4=obj_3.getCondition() |
						obj_4.getTarget().hasName("__builtin_expect")
						and obj_4.getArgument(1) instanceof Literal
					)
				)
			)
		)
	)
	and target_9.getTarget()=vinitial_fsize_10720
}

*/
predicate func_10(Variable voffset_10647, VariableAccess target_10) {
	exists(RemExpr obj_0 | obj_0=target_10.getParent() |
		exists(EQExpr obj_1 | obj_1=obj_0.getParent() |
			exists(NotExpr obj_2 | obj_2=obj_1.getParent() |
				exists(FunctionCall obj_3 | obj_3=obj_2.getParent() |
					exists(IfStmt obj_4 | obj_4=obj_3.getParent() |
						exists(FunctionCall obj_5 | obj_5=obj_4.getCondition() |
							obj_5.getTarget().hasName("__builtin_expect")
							and obj_5.getArgument(1) instanceof Literal
						)
					)
				)
			)
		)
	)
	and target_10.getTarget()=voffset_10647
}

predicate func_11(Variable vspace_10698, EqualityOperation target_18, ExprStmt target_19, ExprStmt target_11) {
	exists(FunctionCall obj_0 | obj_0=target_11.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getArgument(0) |
			obj_1.getTarget().getName()="id"
			and obj_1.getQualifier().(VariableAccess).getTarget()=vspace_10698
		)
		and obj_0.getTarget().hasName("fil_space_close")
	)
	and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
	and target_11.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_12(EqualityOperation target_18, Function func, ReturnStmt target_12) {
	target_12.getExpr().(Literal).getValue()="0"
	and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
	and target_12.getEnclosingFunction() = func
}

predicate func_14(Variable voffset_10647, Variable vphy_page_size_10714, NotExpr target_14) {
	exists(EqualityOperation obj_0 | obj_0=target_14.getOperand() |
		exists(RemExpr obj_1 | obj_1=obj_0.getLeftOperand() |
			obj_1.getLeftOperand().(VariableAccess).getTarget()=voffset_10647
			and obj_1.getRightOperand().(VariableAccess).getTarget()=vphy_page_size_10714
		)
		and obj_0.getRightOperand() instanceof Literal
	)
}

predicate func_15(Variable voffset_10647, Variable vsize_10652, Variable vinitial_fsize_10720, RelationalOperation target_15) {
	exists(AddExpr obj_0 | obj_0=target_15.getLesserOperand() |
		obj_0.getLeftOperand().(VariableAccess).getTarget()=voffset_10647
		and obj_0.getRightOperand().(VariableAccess).getTarget()=vsize_10652
	)
	and  (target_15 instanceof GEExpr or target_15 instanceof LEExpr)
	and target_15.getGreaterOperand().(VariableAccess).getTarget()=vinitial_fsize_10720
}

predicate func_16(Variable vfile_10708, Variable vphy_page_size_10714, Variable vinitial_fsize_10720, FunctionCall target_16) {
	target_16.getTarget().hasName("fil_write_zeros")
	and target_16.getArgument(0).(VariableAccess).getTarget()=vfile_10708
	and target_16.getArgument(1).(VariableAccess).getTarget()=vphy_page_size_10714
	and target_16.getArgument(2).(VariableAccess).getTarget()=vinitial_fsize_10720
	and target_16.getArgument(3).(VariableAccess).getTarget().getType().hasName("os_offset_t")
	and target_16.getArgument(4).(Literal).getValue()="0"
}

predicate func_17(Variable vsize_10652, EqualityOperation target_17) {
	target_17.getLeftOperand().(VariableAccess).getTarget()=vsize_10652
	and target_17.getRightOperand().(Literal).getValue()="0"
}

predicate func_18(Function func, EqualityOperation target_18) {
	target_18.getLeftOperand().(VariableAccess).getTarget().getType().hasName("dberr_t")
	and target_18.getEnclosingFunction() = func
}

predicate func_19(Variable vspace_10698, Variable vfile_10708, ExprStmt target_19) {
	exists(AssignExpr obj_0 | obj_0=target_19.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getLValue() |
			obj_1.getTarget().getName()="size"
			and obj_1.getQualifier().(VariableAccess).getTarget()=vspace_10698
		)
		and exists(PointerFieldAccess obj_2 | obj_2=obj_0.getRValue() |
			obj_2.getTarget().getName()="size"
			and obj_2.getQualifier().(VariableAccess).getTarget()=vfile_10708
		)
	)
}

from Function func, Variable voffset_10647, Variable vsize_10652, Variable vspace_10698, Variable vfile_10708, Variable vphy_page_size_10714, Variable vinitial_fsize_10720, StringLiteral target_0, StringLiteral target_1, PointerFieldAccess target_6, VariableAccess target_10, ExprStmt target_11, ReturnStmt target_12, NotExpr target_14, RelationalOperation target_15, FunctionCall target_16, EqualityOperation target_17, EqualityOperation target_18, ExprStmt target_19
where
func_0(func, target_0)
and func_1(func, target_1)
and not func_2(vphy_page_size_10714, vinitial_fsize_10720, target_14, target_15)
and not func_4(vfile_10708, vinitial_fsize_10720, target_16)
and not func_5(voffset_10647, vsize_10652, target_15, target_17)
and func_6(vspace_10698, target_6)
and func_10(voffset_10647, target_10)
and func_11(vspace_10698, target_18, target_19, target_11)
and func_12(target_18, func, target_12)
and func_14(voffset_10647, vphy_page_size_10714, target_14)
and func_15(voffset_10647, vsize_10652, vinitial_fsize_10720, target_15)
and func_16(vfile_10708, vphy_page_size_10714, vinitial_fsize_10720, target_16)
and func_17(vsize_10652, target_17)
and func_18(func, target_18)
and func_19(vspace_10698, vfile_10708, target_19)
and voffset_10647.getType().hasName("os_offset_t")
and vsize_10652.getType().hasName("os_offset_t")
and vspace_10698.getType().hasName("fil_space_t *")
and vfile_10708.getType().hasName("fil_node_t *")
and vphy_page_size_10714.getType().hasName("size_t")
and vinitial_fsize_10720.getType().hasName("os_offset_t")
and voffset_10647.(LocalVariable).getFunction() = func
and vsize_10652.(LocalVariable).getFunction() = func
and vspace_10698.(LocalVariable).getFunction() = func
and vfile_10708.(LocalVariable).getFunction() = func
and vphy_page_size_10714.(LocalVariable).getFunction() = func
and vinitial_fsize_10720.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
