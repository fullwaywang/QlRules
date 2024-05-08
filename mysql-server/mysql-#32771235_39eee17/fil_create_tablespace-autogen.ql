/**
 * @name mysql-server-39eee179057e92fa7f21094812ff8008598bc065-fil_create_tablespace
 * @id cpp/mysql-server/39eee179057e92fa7f21094812ff8008598bc065/filcreatetablespace
 * @description mysql-server-39eee179057e92fa7f21094812ff8008598bc065-storage/innobase/fil/fil0fil.cc-fil_create_tablespace mysql-#32771235
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpunch_err_5611, BlockStmt target_22, ExprStmt target_19, VariableAccess target_0) {
	target_0.getTarget()=vpunch_err_5611
	and target_0.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_22
	and target_19.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getLocation())
}

predicate func_1(Variable vpunch_hole_5608, IfStmt target_23, VariableAccess target_1) {
	exists(AssignExpr obj_0 | obj_0=target_1.getParent() |
		obj_0.getLValue() = target_1
		and obj_0.getRValue().(Literal).getValue()="0"
	)
	and target_1.getTarget()=vpunch_hole_5608
	and target_23.getCondition().(VariableAccess).getLocation().isBefore(target_1.getLocation())
}

/*predicate func_2(Variable vpunch_hole_5608, IfStmt target_23, Literal target_2) {
	target_2.getValue()="0"
	and not target_2.getValue()="1"
	and target_2.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpunch_hole_5608
	and target_23.getCondition().(VariableAccess).getLocation().isBefore(target_2.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
}

*/
predicate func_3(Variable vpunch_hole_5608, BlockStmt target_24, VariableAccess target_3) {
	target_3.getTarget()=vpunch_hole_5608
	and target_3.getParent().(IfStmt).getThen()=target_24
}

predicate func_4(Parameter vsize_5507, Variable vfile_5508, Variable vpunch_err_5611, FunctionCall target_4) {
	exists(ValueFieldAccess obj_0 | obj_0=target_4.getArgument(0) |
		obj_0.getTarget().getName()="m_file"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vfile_5508
	)
	and exists(MulExpr obj_1 | obj_1=target_4.getArgument(2) |
		obj_1.getLeftOperand().(VariableAccess).getTarget()=vsize_5507
		and obj_1.getRightOperand() instanceof FunctionCall
	)
	and exists(AssignExpr obj_2 | obj_2=target_4.getParent() |
		obj_2.getRValue() = target_4
		and obj_2.getLValue().(VariableAccess).getTarget()=vpunch_err_5611
	)
	and target_4.getTarget().hasName("os_file_punch_hole")
	and not target_4.getTarget().hasName("os_file_write_zeros")
	and target_4.getArgument(1).(Literal).getValue()="0"
}

predicate func_5(Variable vatomic_write_5565, BlockStmt target_25, ExprStmt target_14) {
exists(LogicalOrExpr target_5 |
	exists(LogicalAndExpr obj_0 | obj_0=target_5.getRightOperand() |
		obj_0.getLeftOperand().(VariableAccess).getType().hasName("bool")
		and obj_0.getRightOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vatomic_write_5565
	)
	and target_5.getLeftOperand() instanceof NotExpr
	and target_5.getParent().(IfStmt).getThen()=target_25
	and target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getRightOperand().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(VariableAccess).getLocation())
)
}

predicate func_8(Parameter vpath_5506, Variable vfile_5508, Variable vsz_5566, FunctionCall target_26, ExprStmt target_27, ValueFieldAccess target_28, ExprStmt target_29) {
exists(Initializer target_8 |
	exists(FunctionCall obj_0 | obj_0=target_8.getExpr() |
		obj_0.getTarget().hasName("os_file_write_zeros")
		and obj_0.getArgument(0).(VariableAccess).getTarget()=vfile_5508
		and obj_0.getArgument(1).(VariableAccess).getTarget()=vpath_5506
		and obj_0.getArgument(2) instanceof FunctionCall
		and obj_0.getArgument(3).(Literal).getValue()="0"
		and obj_0.getArgument(4).(VariableAccess).getTarget()=vsz_5566
		and obj_0.getArgument(5).(VariableAccess).getType().hasName("bool")
	)
	and exists(FunctionCall obj_1 | obj_1=target_8.getExpr() |
		obj_1.getArgument(1).(VariableAccess).getLocation().isBefore(target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and obj_1.getArgument(0).(VariableAccess).getLocation().isBefore(target_28.getQualifier().(VariableAccess).getLocation())
	)
	and target_26.getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
	and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
)
}

predicate func_13(Parameter vpath_5506, Variable vsz_5566, ExprStmt target_30, ExprStmt target_29) {
exists(FunctionCall target_13 |
	exists(FunctionCall obj_0 | obj_0=target_13.getQualifier() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getQualifier() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getQualifier() |
				exists(FunctionCall obj_3 | obj_3=obj_2.getQualifier() |
					exists(FunctionCall obj_4 | obj_4=obj_3.getQualifier() |
						obj_4.getTarget().hasName("operator<<")
						and obj_4.getArgument(0).(StringLiteral).getValue()="Error while writing "
					)
					and obj_3.getTarget().hasName("operator<<")
					and obj_3.getArgument(0).(VariableAccess).getTarget()=vsz_5566
				)
				and obj_2.getTarget().hasName("operator<<")
				and obj_2.getArgument(0).(StringLiteral).getValue()=" zeroes to "
			)
			and obj_1.getTarget().hasName("operator<<")
			and obj_1.getArgument(0).(VariableAccess).getTarget()=vpath_5506
		)
		and obj_0.getTarget().hasName("operator<<")
		and obj_0.getArgument(0).(StringLiteral).getValue()=" starting at offset "
	)
	and target_13.getTarget().hasName("operator<<")
	and target_13.getArgument(0).(Literal).getValue()="0"
	and target_30.getExpr().(ConstructorCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_13.getQualifier().(FunctionCall).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
	and target_13.getQualifier().(FunctionCall).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
)
}

predicate func_14(Variable vatomic_write_5565, EqualityOperation target_31, ExprStmt target_14) {
	exists(AssignExpr obj_0 | obj_0=target_14.getExpr() |
		obj_0.getLValue().(VariableAccess).getTarget()=vatomic_write_5565
		and obj_0.getRValue().(Literal).getValue()="1"
	)
	and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_31
}

predicate func_15(Variable vsuccess_5511, BlockStmt target_25, NotExpr target_15) {
	target_15.getOperand().(VariableAccess).getTarget()=vsuccess_5511
	and target_15.getParent().(IfStmt).getThen()=target_25
}

predicate func_16(Variable vpage_size_5520, FunctionCall target_16) {
	target_16.getTarget().hasName("physical")
	and target_16.getQualifier().(VariableAccess).getTarget()=vpage_size_5520
	and target_16.getParent().(MulExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_18(Variable vatomic_write_5565, AssignExpr target_18) {
	target_18.getLValue().(VariableAccess).getTarget()=vatomic_write_5565
	and target_18.getRValue() instanceof Literal
}

predicate func_19(Variable vpunch_err_5611, VariableAccess target_3, ExprStmt target_19) {
	exists(AssignExpr obj_0 | obj_0=target_19.getExpr() |
		obj_0.getLValue().(VariableAccess).getTarget()=vpunch_err_5611
		and obj_0.getRValue() instanceof FunctionCall
	)
	and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_20(Variable vfile_5508, ExprStmt target_27, VariableAccess target_20) {
	target_20.getTarget()=vfile_5508
	and target_20.getParent().(ValueFieldAccess).getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
	and target_20.getLocation().isBefore(target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
}

predicate func_21(Parameter vsize_5507, MulExpr target_32, FunctionCall target_33, VariableAccess target_21) {
	target_21.getTarget()=vsize_5507
	and target_21.getParent().(MulExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
	and target_32.getLeftOperand().(VariableAccess).getLocation().isBefore(target_21.getLocation())
	and target_21.getLocation().isBefore(target_33.getArgument(1).(VariableAccess).getLocation())
}

predicate func_22(Variable vpunch_hole_5608, BlockStmt target_22) {
	exists(ExprStmt obj_0 | obj_0=target_22.getStmt(0) |
		exists(AssignExpr obj_1 | obj_1=obj_0.getExpr() |
			obj_1.getLValue().(VariableAccess).getTarget()=vpunch_hole_5608
			and obj_1.getRValue() instanceof Literal
		)
	)
}

predicate func_23(Variable vpunch_hole_5608, Variable vpunch_err_5611, IfStmt target_23) {
	exists(BlockStmt obj_0 | obj_0=target_23.getThen() |
		exists(IfStmt obj_1 | obj_1=obj_0.getStmt(2) |
			exists(BlockStmt obj_2 | obj_2=obj_1.getThen() |
				exists(ExprStmt obj_3 | obj_3=obj_2.getStmt(0) |
					exists(AssignExpr obj_4 | obj_4=obj_3.getExpr() |
						obj_4.getLValue().(VariableAccess).getTarget()=vpunch_hole_5608
						and obj_4.getRValue() instanceof Literal
					)
				)
			)
			and obj_1.getCondition().(EqualityOperation).getLeftOperand().(VariableAccess).getTarget()=vpunch_err_5611
		)
		and obj_0.getStmt(1) instanceof ExprStmt
	)
	and target_23.getCondition().(VariableAccess).getTarget()=vpunch_hole_5608
}

predicate func_24(Variable vpunch_hole_5608, Variable vpunch_err_5611, BlockStmt target_24) {
	exists(IfStmt obj_0 | obj_0=target_24.getStmt(2) |
		exists(BlockStmt obj_1 | obj_1=obj_0.getThen() |
			exists(ExprStmt obj_2 | obj_2=obj_1.getStmt(0) |
				exists(AssignExpr obj_3 | obj_3=obj_2.getExpr() |
					obj_3.getLValue().(VariableAccess).getTarget()=vpunch_hole_5608
					and obj_3.getRValue() instanceof Literal
				)
			)
		)
		and obj_0.getCondition().(EqualityOperation).getLeftOperand().(VariableAccess).getTarget()=vpunch_err_5611
	)
	and target_24.getStmt(1) instanceof ExprStmt
}

predicate func_25(Parameter vpath_5506, Variable vfile_5508, Variable vsuccess_5511, Variable vsz_5566, BlockStmt target_25) {
	exists(ExprStmt obj_0 | obj_0=target_25.getStmt(1) |
		exists(AssignExpr obj_1 | obj_1=obj_0.getExpr() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getRValue() |
				obj_2.getTarget().hasName("os_file_set_size")
				and obj_2.getArgument(0).(VariableAccess).getTarget()=vpath_5506
				and obj_2.getArgument(1).(VariableAccess).getTarget()=vfile_5508
				and obj_2.getArgument(2).(Literal).getValue()="0"
				and obj_2.getArgument(3).(VariableAccess).getTarget()=vsz_5566
				and obj_2.getArgument(4).(VariableAccess).getTarget().getType().hasName("bool")
				and obj_2.getArgument(5).(Literal).getValue()="1"
			)
			and obj_1.getLValue().(VariableAccess).getTarget()=vsuccess_5511
		)
	)
	and target_25.getStmt(0).(ExprStmt).getExpr() instanceof AssignExpr
}

predicate func_26(Parameter vpath_5506, Variable vfile_5508, FunctionCall target_26) {
	target_26.getTarget().hasName("os_is_sparse_file_supported")
	and target_26.getArgument(0).(VariableAccess).getTarget()=vpath_5506
	and target_26.getArgument(1).(VariableAccess).getTarget()=vfile_5508
}

predicate func_27(Parameter vpath_5506, Variable vfile_5508, Variable vpage_size_5520, ExprStmt target_27) {
	exists(AssignExpr obj_0 | obj_0=target_27.getExpr() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getRValue() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getArgument(5) |
				obj_2.getTarget().hasName("physical")
				and obj_2.getQualifier().(VariableAccess).getTarget()=vpage_size_5520
			)
			and obj_1.getTarget().hasName("pfs_os_file_write_func")
			and obj_1.getArgument(0).(VariableAccess).getTarget().getType().hasName("IORequest")
			and obj_1.getArgument(1).(VariableAccess).getTarget()=vpath_5506
			and obj_1.getArgument(2).(VariableAccess).getTarget()=vfile_5508
			and obj_1.getArgument(3).(VariableAccess).getTarget().getType().hasName("unsigned char *")
			and obj_1.getArgument(4).(Literal).getValue()="0"
			and obj_1.getArgument(6) instanceof StringLiteral
			and obj_1.getArgument(7) instanceof Literal
		)
		and obj_0.getLValue().(VariableAccess).getTarget().getType().hasName("dberr_t")
	)
}

predicate func_28(Variable vfile_5508, ValueFieldAccess target_28) {
	target_28.getTarget().getName()="m_file"
	and target_28.getQualifier().(VariableAccess).getTarget()=vfile_5508
}

predicate func_29(Parameter vpath_5506, Variable vfile_5508, Variable vsuccess_5511, Variable vsz_5566, ExprStmt target_29) {
	exists(AssignExpr obj_0 | obj_0=target_29.getExpr() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getRValue() |
			obj_1.getTarget().hasName("os_file_set_size")
			and obj_1.getArgument(0).(VariableAccess).getTarget()=vpath_5506
			and obj_1.getArgument(1).(VariableAccess).getTarget()=vfile_5508
			and obj_1.getArgument(2).(Literal).getValue()="0"
			and obj_1.getArgument(3).(VariableAccess).getTarget()=vsz_5566
			and obj_1.getArgument(4).(VariableAccess).getTarget().getType().hasName("bool")
			and obj_1.getArgument(5).(Literal).getValue()="1"
		)
		and obj_0.getLValue().(VariableAccess).getTarget()=vsuccess_5511
	)
}

predicate func_30(Parameter vpath_5506, Variable vsz_5566, ExprStmt target_30) {
	exists(ConstructorCall obj_0 | obj_0=target_30.getExpr() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getArgument(4) |
			obj_1.getTarget().hasName("strerror")
			and obj_1.getArgument(0).(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		)
		and obj_0.getArgument(0).(Literal).getValue()="12128"
		and obj_0.getArgument(1).(VariableAccess).getTarget()=vpath_5506
		and obj_0.getArgument(2).(VariableAccess).getTarget()=vsz_5566
		and obj_0.getArgument(3).(VariableAccess).getTarget().getType().hasName("int")
	)
}

predicate func_31(Function func, EqualityOperation target_31) {
	target_31.getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
	and target_31.getRightOperand().(Literal).getValue()="0"
	and target_31.getEnclosingFunction() = func
}

predicate func_32(Parameter vsize_5507, Variable vpage_size_5520, MulExpr target_32) {
	exists(FunctionCall obj_0 | obj_0=target_32.getRightOperand() |
		obj_0.getTarget().hasName("physical")
		and obj_0.getQualifier().(VariableAccess).getTarget()=vpage_size_5520
	)
	and target_32.getLeftOperand().(VariableAccess).getTarget()=vsize_5507
}

predicate func_33(Parameter vpath_5506, Parameter vsize_5507, Variable vatomic_write_5565, Variable vpunch_hole_5608, FunctionCall target_33) {
	target_33.getTarget().hasName("create_node")
	and target_33.getQualifier().(VariableAccess).getTarget().getType().hasName("Fil_shard *")
	and target_33.getArgument(0).(VariableAccess).getTarget()=vpath_5506
	and target_33.getArgument(1).(VariableAccess).getTarget()=vsize_5507
	and target_33.getArgument(2).(VariableAccess).getTarget().getType().hasName("fil_space_t *")
	and target_33.getArgument(3).(Literal).getValue()="0"
	and target_33.getArgument(4).(VariableAccess).getTarget()=vpunch_hole_5608
	and target_33.getArgument(5).(VariableAccess).getTarget()=vatomic_write_5565
}

from Function func, Parameter vpath_5506, Parameter vsize_5507, Variable vfile_5508, Variable vsuccess_5511, Variable vpage_size_5520, Variable vatomic_write_5565, Variable vsz_5566, Variable vpunch_hole_5608, Variable vpunch_err_5611, VariableAccess target_0, VariableAccess target_1, VariableAccess target_3, FunctionCall target_4, ExprStmt target_14, NotExpr target_15, FunctionCall target_16, AssignExpr target_18, ExprStmt target_19, VariableAccess target_20, VariableAccess target_21, BlockStmt target_22, IfStmt target_23, BlockStmt target_24, BlockStmt target_25, FunctionCall target_26, ExprStmt target_27, ValueFieldAccess target_28, ExprStmt target_29, ExprStmt target_30, EqualityOperation target_31, MulExpr target_32, FunctionCall target_33
where
func_0(vpunch_err_5611, target_22, target_19, target_0)
and func_1(vpunch_hole_5608, target_23, target_1)
and func_3(vpunch_hole_5608, target_24, target_3)
and func_4(vsize_5507, vfile_5508, vpunch_err_5611, target_4)
and not func_5(vatomic_write_5565, target_25, target_14)
and not func_8(vpath_5506, vfile_5508, vsz_5566, target_26, target_27, target_28, target_29)
and not func_13(vpath_5506, vsz_5566, target_30, target_29)
and func_14(vatomic_write_5565, target_31, target_14)
and func_15(vsuccess_5511, target_25, target_15)
and func_16(vpage_size_5520, target_16)
and func_18(vatomic_write_5565, target_18)
and func_19(vpunch_err_5611, target_3, target_19)
and func_20(vfile_5508, target_27, target_20)
and func_21(vsize_5507, target_32, target_33, target_21)
and func_22(vpunch_hole_5608, target_22)
and func_23(vpunch_hole_5608, vpunch_err_5611, target_23)
and func_24(vpunch_hole_5608, vpunch_err_5611, target_24)
and func_25(vpath_5506, vfile_5508, vsuccess_5511, vsz_5566, target_25)
and func_26(vpath_5506, vfile_5508, target_26)
and func_27(vpath_5506, vfile_5508, vpage_size_5520, target_27)
and func_28(vfile_5508, target_28)
and func_29(vpath_5506, vfile_5508, vsuccess_5511, vsz_5566, target_29)
and func_30(vpath_5506, vsz_5566, target_30)
and func_31(func, target_31)
and func_32(vsize_5507, vpage_size_5520, target_32)
and func_33(vpath_5506, vsize_5507, vatomic_write_5565, vpunch_hole_5608, target_33)
and vpath_5506.getType().hasName("const char *")
and vsize_5507.getType().hasName("page_no_t")
and vfile_5508.getType().hasName("pfs_os_file_t")
and vsuccess_5511.getType().hasName("bool")
and vpage_size_5520.getType().hasName("const page_size_t")
and vatomic_write_5565.getType().hasName("bool")
and vsz_5566.getType().hasName("const ulonglong")
and vpunch_hole_5608.getType().hasName("bool")
and vpunch_err_5611.getType().hasName("dberr_t")
and vpath_5506.getFunction() = func
and vsize_5507.getFunction() = func
and vfile_5508.(LocalVariable).getFunction() = func
and vsuccess_5511.(LocalVariable).getFunction() = func
and vpage_size_5520.(LocalVariable).getFunction() = func
and vatomic_write_5565.(LocalVariable).getFunction() = func
and vsz_5566.(LocalVariable).getFunction() = func
and vpunch_hole_5608.(LocalVariable).getFunction() = func
and vpunch_err_5611.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
